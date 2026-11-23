//! DNS answers → which name each IP address was looked up as.
//!
//! The input comes straight off the network (any host on the LAN can send a UDP packet from
//! port 53), so the parser never panics, follows at most a few compression pointers, and keeps
//! only names made of plain hostname characters: they end up in a terminal and a web page.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const MAX_JUMPS: usize = 16;
const MAX_NAME: usize = 253;

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// Reads a possibly compressed name at `pos`. Returns it lowercased with no trailing dot,
/// and the position right after it in the message.
fn read_name(m: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *m.get(pos)? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => break,
            0x00 => {
                let label = m.get(pos + 1..pos + 1 + len)?;
                if !label.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|&b| b.to_ascii_lowercase() as char));
                if name.len() > MAX_NAME {
                    return None;
                }
                pos += 1 + len;
            }
            0xc0 => {
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None; // pointer loop
                }
                end.get_or_insert(pos + 2);
                pos = (u16_at(m, pos)? & 0x3fff) as usize;
            }
            _ => return None, // 0x40/0x80: obsolete label types
        }
    }
    Some((name, end.unwrap_or(pos + 1)))
}

/// The watched cgroup and the DNS message inside a ring buffer sample
/// (`struct dns_event`: u32 length, 4 pad bytes, u64 cgroup id, data).
pub fn payload(sample: &[u8]) -> Option<(u64, &[u8])> {
    let len = u32::from_ne_bytes(sample.get(..4)?.try_into().ok()?) as usize;
    let cgroup = u64::from_ne_bytes(sample.get(8..16)?.try_into().ok()?);
    Some((cgroup, sample.get(16..16 + len)?))
}

/// Every A/AAAA address in a successful response, paired with the name that was asked
/// (the question), not the CDN alias at the end of a CNAME chain: `api.github.com`
/// says more than `lb-140-82-112-5-iad.github.com`.
pub fn answers(m: &[u8]) -> Vec<(IpAddr, String)> {
    parse(m).unwrap_or_default()
}

fn parse(m: &[u8]) -> Option<Vec<(IpAddr, String)>> {
    let flags = u16_at(m, 2)?;
    let is_response = flags & 0x8000 != 0;
    let no_error = flags & 0x000f == 0;
    if !is_response || !no_error || u16_at(m, 4)? != 1 {
        return None;
    }
    let ancount = u16_at(m, 6)?;
    let (qname, pos) = read_name(m, 12)?;
    if qname.is_empty() {
        return None;
    }
    let mut pos = pos + 4; // QTYPE, QCLASS
    let mut out = Vec::new();
    for _ in 0..ancount {
        // Truncated by the kernel copy (DNS_MAX): keep what was complete.
        let Some((_, p)) = read_name(m, pos) else { break };
        let (Some(typ), Some(rdlen)) = (u16_at(m, p), u16_at(m, p + 8)) else { break };
        let start = p + 10;
        let Some(rdata) = m.get(start..start + rdlen as usize) else { break };
        let ip = match (typ, rdata.len()) {
            (TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
            (TYPE_AAAA, 16) => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?))),
            _ => None,
        };
        out.extend(ip.map(|ip| (ip, qname.clone())));
        pos = start + rdata.len();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in n.split('.') {
            v.push(l.len() as u8);
            v.extend(l.as_bytes());
        }
        v.push(0);
        v
    }

    /// Response to `qname`: a CNAME to cdn.example.net, then the given records, names compressed.
    fn response(qname: &str, records: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1 + records.len() as u8, 0, 0, 0, 0];
        m.extend(name(qname));
        m.extend([0, 1, 0, 1]);
        let cname = name("cdn.example.net");
        m.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, cname.len() as u8]);
        let cname_at = m.len();
        m.extend(cname);
        for (typ, rdata) in records {
            m.extend([0xc0, cname_at as u8]);
            m.extend(typ.to_be_bytes());
            m.extend([0, 1, 0, 0, 0, 60, 0, rdata.len() as u8]);
            m.extend(*rdata);
        }
        m
    }

    #[test]
    fn names_a_and_aaaa_after_a_cname_with_the_question() {
        let v6: Ipv6Addr = "2606:4700::1".parse().unwrap();
        let m = response("API.GitHub.com", &[(TYPE_A, &[140, 82, 112, 5]), (TYPE_AAAA, &v6.octets())]);
        let got = answers(&m);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("140.82.112.5".parse().unwrap(), "api.github.com".into()));
        assert_eq!(got[1], (IpAddr::V6(v6), "api.github.com".into()));
    }

    #[test]
    fn keeps_complete_records_of_a_truncated_answer() {
        let m = response("a.example.com", &[(TYPE_A, &[1, 2, 3, 4]), (TYPE_A, &[5, 6, 7, 8])]);
        let got = answers(&m[..m.len() - 2]);
        assert_eq!(got, vec![("1.2.3.4".parse().unwrap(), "a.example.com".into())]);
    }

    #[test]
    fn rejects_queries_errors_loops_and_hostile_names() {
        let ok = response("a.example.com", &[(TYPE_A, &[1, 2, 3, 4])]);
        let mut query = ok.clone();
        query[2] &= 0x7f;
        let mut nxdomain = ok.clone();
        nxdomain[3] |= 3;
        let mut looped = ok.clone();
        looped[12..14].copy_from_slice(&[0xc0, 12]); // question name points at itself
        let html = response("x<script>.example.com", &[(TYPE_A, &[1, 2, 3, 4])]);
        for m in [query, nxdomain, looped, html] {
            assert!(answers(&m).is_empty());
        }
        // Never panics on any prefix of a valid message.
        for i in 0..ok.len() {
            answers(&ok[..i]);
        }
    }
}
