// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stateless fast-fail replies to canonical denied IPv4 TCP/UDP traffic.
use crate::egress::EgressPolicy;
use crate::egress::EgressPolicyMode;

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl EgressPolicy {
    /// Permit only canonical gateway resolution so denial can return a reply.
    /// The legacy authorize-frame contract continues to deny all ARP in DenyAll.
    pub fn permits_denial_neighbor(&self, frame: &[u8]) -> bool {
        if frame.len() < 42 || frame[12..14] != [0x08, 0x06] {
            return false;
        }
        let mut neighbor = self.clone();
        neighbor.mode = EgressPolicyMode::AllowList(vec![
            format!("{}/32", self.gateway_ipv4)
                .parse()
                .expect("valid gateway prefix"),
        ]);
        neighbor.next_hops = vec![self.gateway_ipv4];
        neighbor.authorize_frame(frame, frame.len()).is_ok()
    }

    /// Construct TCP reset or ICMP administratively prohibited. Invalid,
    /// fragmented, spoofed, non-IP, and reset frames receive no reply.
    pub fn denial_reply(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < 42
            || frame[12..14] != [0x08, 0x00]
            || frame[14] != 0x45
            || frame[6..12] != self.guest_mac.to_bytes()
            || frame[26..30] != self.guest_ipv4.octets()
            || u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0
        {
            return None;
        }
        let ip_len = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
        if ip_len < 28 || 14 + ip_len > frame.len() {
            return None;
        }
        let proto = frame[23];
        let transport = &frame[34..14 + ip_len];
        let mut payload = if proto == 6 {
            if transport.len() < 20 || transport[13] & 4 != 0 {
                return None;
            }
            let tcp_header = usize::from(transport[12] >> 4) * 4;
            if !(20..=transport.len()).contains(&tcp_header) {
                return None;
            }
            let mut tcp = vec![0u8; 20];
            tcp[0..2].copy_from_slice(&transport[2..4]);
            tcp[2..4].copy_from_slice(&transport[0..2]);
            tcp[12] = 0x50;
            if transport[13] & 0x10 != 0 {
                tcp[4..8].copy_from_slice(&transport[8..12]);
                tcp[13] = 4;
            } else {
                let seq = u32::from_be_bytes(transport[4..8].try_into().unwrap());
                let advance = (transport.len() - tcp_header) as u32
                    + u32::from(transport[13] & 2 != 0)
                    + u32::from(transport[13] & 1 != 0);
                tcp[8..12].copy_from_slice(&seq.wrapping_add(advance).to_be_bytes());
                tcp[13] = 0x14;
            }
            let mut pseudo = frame[30..34].to_vec();
            pseudo.extend_from_slice(&frame[26..30]);
            pseudo.extend_from_slice(&[0, 6, 0, 20]);
            pseudo.extend_from_slice(&tcp);
            tcp[16..18].copy_from_slice(&checksum(&pseudo).to_be_bytes());
            tcp
        } else if proto == 17 {
            let mut icmp = vec![3, 13, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&frame[14..42]);
            let crc = checksum(&icmp);
            icmp[2..4].copy_from_slice(&crc.to_be_bytes());
            icmp
        } else {
            return None;
        };
        let mut reply = vec![0u8; 34];
        reply[0..6].copy_from_slice(&frame[6..12]);
        reply[6..12].copy_from_slice(&frame[0..6]);
        reply[12..14].copy_from_slice(&[8, 0]);
        reply[14] = 0x45;
        reply[16..18].copy_from_slice(&(20u16 + payload.len() as u16).to_be_bytes());
        reply[22] = 64;
        reply[23] = if proto == 6 { 6 } else { 1 };
        reply[26..30].copy_from_slice(&frame[30..34]);
        reply[30..34].copy_from_slice(&frame[26..30]);
        let crc = checksum(&reply[14..34]);
        reply[24..26].copy_from_slice(&crc.to_be_bytes());
        reply.append(&mut payload);
        Some(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;
    #[test]
    fn reset_matches_sequence_and_checksums_and_refuses_spoofing() {
        let guest = Ipv4Addr::new(10, 0, 0, 2);
        let mac = MacAddress::new([0x52, 0x54, 0, 0, 0, 2]);
        let policy = EgressPolicy::bind(
            guest,
            24,
            mac,
            Ipv4Addr::new(10, 0, 0, 1),
            EgressPolicyMode::DenyAll,
        )
        .unwrap();
        let mut frame = vec![0; 54];
        frame[6..12].copy_from_slice(&mac.to_bytes());
        frame[12..14].copy_from_slice(&[8, 0]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40u16.to_be_bytes());
        frame[23] = 6;
        frame[26..30].copy_from_slice(&guest.octets());
        frame[30..34].copy_from_slice(&[192, 0, 2, 1]);
        frame[34..36].copy_from_slice(&1234u16.to_be_bytes());
        frame[36..38].copy_from_slice(&443u16.to_be_bytes());
        frame[38..42].copy_from_slice(&100u32.to_be_bytes());
        frame[46] = 0x50;
        frame[47] = 2;
        let reply = policy.denial_reply(&frame).unwrap();
        assert_eq!(reply[47], 0x14);
        assert_eq!(reply[42..46], 101u32.to_be_bytes());
        assert_eq!(checksum(&reply[14..34]), 0);
        let mut pseudo = reply[26..34].to_vec();
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo.extend_from_slice(&reply[34..]);
        assert_eq!(checksum(&pseudo), 0);
        frame[26] = 99;
        assert!(policy.denial_reply(&frame).is_none());
        // The removed-reply negative control has no RX packet to unblock connect.
        assert!(policy.authorize_frame(&frame, frame.len()).is_err());
    }
}
