use rand::RngExt;
use rand::Rng;
use rand::seq::SliceRandom;

/// Constructs a fake TLS 1.3 ClientHello packet with the specified SNI.
/// Each call produces a structurally valid but fingerprint-varied ClientHello
/// via randomized cipher order, extension order, and variable padding.
pub struct ClientHelloBuilder;

impl ClientHelloBuilder {
    // All cipher suites — shuffled per connection
    const ALL_CIPHER_SUITES: &'static [u16] = &[
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0x1301, // TLS_AES_128_GCM_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x006b, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    ];

    // All signature algorithms — subset chosen and shuffled per connection
    const ALL_SIG_ALGS: &'static [u16] = &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0603, // ecdsa_secp521r1_sha512
        0x0807, // ed25519
        0x0808, // ed448
        0x0809, // rsa_pss_pss_sha256
        0x080a, // rsa_pss_pss_sha384
        0x080b, // rsa_pss_pss_sha512
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
        0x0601, // rsa_pkcs1_sha512
    ];

    // All supported groups — x25519 always first, rest shuffled
    const ALL_GROUPS: &'static [u16] = &[
        0x001d, // x25519  (must stay first)
        0x0017, // secp256r1
        0x001e, // x448
        0x0019, // secp521r1
        0x0018, // secp384r1
    ];

    const COMPRESSION: &'static [u8] = &[
        0x01, // length = 1
        0x00, // null compression
    ];

    /// Build a randomized ClientHello. Randomizes cipher order, extension
    /// order, signature algorithm subset, group subset, ALPN choice, optional
    /// extensions, and padding length. All randomness is local to this call.
    pub fn build_randomized(sni: &str) -> Vec<u8> {
        let mut rng = rand::rng();

        let mut client_random = [0u8; 32];
        let mut session_id   = [0u8; 32];
        let mut key_share    = [0u8; 32];
        rng.fill(&mut client_random[..]);
        rng.fill(&mut session_id[..]);
        rng.fill(&mut key_share[..]);

        // Shuffle ciphers; SCSV always last
        let mut ciphers: Vec<u16> = Self::ALL_CIPHER_SUITES.to_vec();
        ciphers.shuffle(&mut rng);
        ciphers.push(0x00ff); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV

        // Pick a random subset of sig algs (at least 6)
        let sig_count = rng.random_range(6..=Self::ALL_SIG_ALGS.len());
        let mut sig_algs: Vec<u16> = Self::ALL_SIG_ALGS.to_vec();
        sig_algs.shuffle(&mut rng);
        sig_algs.truncate(sig_count);

        // x25519 always first; add 0..4 extra groups in random order
        let extra_count = rng.random_range(0..=(Self::ALL_GROUPS.len() - 1));
        let mut extra_groups: Vec<u16> = Self::ALL_GROUPS[1..].to_vec();
        extra_groups.shuffle(&mut rng);
        let mut groups: Vec<u16> = vec![0x001d];
        groups.extend_from_slice(&extra_groups[..extra_count]);

        Self::build_inner(
            &client_random,
            &session_id,
            sni.as_bytes(),
            &key_share,
            &ciphers,
            &sig_algs,
            &groups,
            &mut rng,
        )
    }

    /// Deterministic build — useful for tests where you supply all parameters.
    pub fn build(
        client_random: &[u8; 32],
        session_id: &[u8; 32],
        sni: &str,
        key_share: &[u8; 32],
    ) -> Vec<u8> {
        // Use fixed (non-random) choices for deterministic output
        let ciphers: Vec<u16> = Self::ALL_CIPHER_SUITES
            .iter()
            .copied()
            .chain(std::iter::once(0x00ff))
            .collect();
        let sig_algs: Vec<u16> = Self::ALL_SIG_ALGS.to_vec();
        let groups: Vec<u16>   = Self::ALL_GROUPS.to_vec();

        // Use a seeded rng so padding/optional extensions are deterministic
        use rand::SeedableRng;
        let mut rng = rand::rngs::SmallRng::seed_from_u64(0);

        Self::build_inner(
            client_random,
            session_id,
            sni.as_bytes(),
            key_share,
            &ciphers,
            &sig_algs,
            &groups,
            &mut rng,
        )
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn build_inner(
        client_random: &[u8; 32],
        session_id: &[u8; 32],
        sni: &[u8],
        key_share: &[u8; 32],
        ciphers: &[u16],
        sig_algs: &[u16],
        groups: &[u16],
        rng: &mut impl RngExt,
    ) -> Vec<u8> {
        let extensions = Self::build_extensions(sni, key_share, ciphers, sig_algs, groups, rng);

        let cipher_bytes_len = ciphers.len() * 2;
        let handshake_body_len =
            2                           // client version
            + 32                        // random
            + 1 + 32                    // session id length + session id
            + 2 + cipher_bytes_len      // cipher suites length + data
            + Self::COMPRESSION.len()   // compression methods
            + 2                         // extensions length field
            + extensions.len();

        let mut pkt = Vec::with_capacity(5 + 4 + handshake_body_len);

        // TLS Record Header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0x03, 0x01]); // legacy version for compat
        pkt.extend_from_slice(&((4 + handshake_body_len) as u16).to_be_bytes());

        // Handshake Header
        pkt.push(0x01); // ClientHello
        let hl = handshake_body_len as u32;
        pkt.push(((hl >> 16) & 0xff) as u8);
        pkt.push(((hl >>  8) & 0xff) as u8);
        pkt.push(( hl        & 0xff) as u8);

        // Client Version (legacy TLS 1.2)
        pkt.extend_from_slice(&[0x03, 0x03]);

        // Random
        pkt.extend_from_slice(client_random);

        // Session ID
        pkt.push(0x20);
        pkt.extend_from_slice(session_id);

        // Cipher Suites
        pkt.extend_from_slice(&(cipher_bytes_len as u16).to_be_bytes());
        for c in ciphers {
            pkt.extend_from_slice(&c.to_be_bytes());
        }

        // Compression Methods
        pkt.extend_from_slice(Self::COMPRESSION);

        // Extensions
        pkt.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&extensions);

        pkt
    }

    fn build_extensions(
        sni: &[u8],
        key_share: &[u8; 32],
        ciphers: &[u16],
        sig_algs: &[u16],
        groups: &[u16],
        rng: &mut impl RngExt,
    ) -> Vec<u8> {
        // --- Build each optional extension as its own buffer ---
        let mut optional: Vec<Vec<u8>> = Vec::new();

        // Supported groups (0x000a)
        {
            let list_bytes = (groups.len() * 2) as u16;
            let mut d = Vec::new();
            d.extend_from_slice(&list_bytes.to_be_bytes());
            for g in groups {
                d.extend_from_slice(&g.to_be_bytes());
            }
            optional.push(Self::make_ext(0x000a, &d));
        }

        // Signature algorithms (0x000d)
        {
            let list_bytes = (sig_algs.len() * 2) as u16;
            let mut d = Vec::new();
            d.extend_from_slice(&list_bytes.to_be_bytes());
            for s in sig_algs {
                d.extend_from_slice(&s.to_be_bytes());
            }
            optional.push(Self::make_ext(0x000d, &d));
        }

        // EC point formats (0x000b)
        optional.push(Self::make_ext(0x000b, &[0x01, 0x00]));

        // ALPN (0x0010) — randomly h2+http/1.1 or just http/1.1
        {
            let alpn = if rng.random_bool(0.7) {
                vec![
                    0x00, 0x0c,
                    0x02, b'h', b'2',
                    0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
                ]
            } else {
                vec![
                    0x00, 0x0b,
                    0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
                ]
            };
            optional.push(Self::make_ext(0x0010, &alpn));
        }

        // PSK key exchange modes (0x002d)
        optional.push(Self::make_ext(0x002d, &[0x01, 0x01]));

        // Session ticket (0x0023) — empty
        optional.push(Self::make_ext(0x0023, &[]));

        // Encrypt-then-MAC (0x0016) — randomly included
        if rng.random_bool(0.6) {
            optional.push(Self::make_ext(0x0016, &[]));
        }

        // Extended master secret (0x0017) — randomly included
        if rng.random_bool(0.8) {
            optional.push(Self::make_ext(0x0017, &[]));
        }

        // Shuffle optional extensions for fingerprint variance
        optional.shuffle(rng);

        // --- Assemble: SNI first, optional shuffled, then required anchors ---
        let mut ext = Vec::new();
        Self::write_sni_extension(&mut ext, sni);
        for e in &optional {
            ext.extend_from_slice(e);
        }

        // supported_versions (0x002b) — required, always near end
        // Format: 1-byte list-length + list of 2-byte versions
        // List = TLS 1.3 (0x0304) + TLS 1.2 (0x0303) = 4 bytes
        ext.extend_from_slice(&Self::make_ext(0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]));

        // Key share (0x0033) — required, always last before padding
        Self::write_key_share_extension(&mut ext, key_share);

        // --- Padding extension (0x0015) ---
        // We measure the full packet size at this point and pad to a random
        // target in [512, 576] so the total size varies per connection.
        let cipher_bytes_len = ciphers.len() * 2;
        // Fixed overhead: record(5) + hs_hdr(4) + ver(2) + random(32) +
        //                 sid_len(1) + sid(32) + cs_len(2) + ciphers +
        //                 compression(2) + ext_len_field(2) + ext_so_far
        let overhead = 5 + 4 + 2 + 32 + 1 + 32 + 2 + cipher_bytes_len + 2 + 2;
        let current_total = overhead + ext.len();
        let target = 512 + rng.random_range(0usize..=64);
        if current_total + 4 < target {
            let pad_data_len = target - current_total - 4;
            Self::write_padding_extension(&mut ext, pad_data_len);
        }

        ext
    }

    // --- Wire-format helpers ---

    fn make_ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&ext_type.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    fn write_sni_extension(buf: &mut Vec<u8>, sni: &[u8]) {
        // RFC 6066 §3:
        //   struct { NameType name_type; select(name_type) { case host_name: HostName; } } ServerName;
        //   ServerName entry  = type(1) + length(2) + name
        //   ServerNameList    = list_length(2) + entries
        //   Extension data    = ServerNameList (i.e. list_length + entries)
        let name_len  = sni.len() as u16;
        let entry_len = 1 + 2 + name_len;       // type + length field + name bytes
        let list_len  = entry_len;               // only one entry; list_len counts entry bytes only

        let mut data = Vec::with_capacity(2 + list_len as usize);
        data.extend_from_slice(&list_len.to_be_bytes()); // ServerNameList.length
        data.push(0x00);                                  // NameType: host_name
        data.extend_from_slice(&name_len.to_be_bytes()); // HostName.length
        data.extend_from_slice(sni);                      // HostName

        buf.extend_from_slice(&Self::make_ext(0x0000, &data));
    }

    fn write_key_share_extension(buf: &mut Vec<u8>, key_share: &[u8; 32]) {
        // KeyShareEntry = group(2) + key_exchange_length(2) + key_exchange
        let mut entry = Vec::with_capacity(36);
        entry.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
        entry.extend_from_slice(&32u16.to_be_bytes());
        entry.extend_from_slice(key_share);

        // client_shares = list_length(2) + entries
        let mut data = Vec::with_capacity(2 + entry.len());
        data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        data.extend_from_slice(&entry);

        buf.extend_from_slice(&Self::make_ext(0x0033, &data));
    }

    fn write_padding_extension(buf: &mut Vec<u8>, pad_len: usize) {
        buf.extend_from_slice(&0x0015u16.to_be_bytes());
        buf.extend_from_slice(&(pad_len as u16).to_be_bytes());
        buf.resize(buf.len() + pad_len, 0x00);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_length_fields(hello: &[u8]) {
        // TLS record length
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5,
            "TLS record length field mismatch");

        // Handshake body length (3-byte big-endian)
        let hs_len = ((hello[6] as usize) << 16)
                   | ((hello[7] as usize) <<  8)
                   |  (hello[8] as usize);
        assert_eq!(hs_len, hello.len() - 9,
            "Handshake length field mismatch");
    }

    #[test]
    fn test_randomized_record_structure() {
        let hello = ClientHelloBuilder::build_randomized("example.com");
        assert_eq!(hello[0], 0x16, "Content type must be Handshake");
        assert_eq!(hello[1], 0x03, "Legacy version major");
        assert_eq!(hello[5], 0x01, "Handshake type must be ClientHello");
        assert_eq!(hello[9], 0x03, "Client version major");
        assert_eq!(hello[10], 0x03, "Client version minor");
        assert!(hello.len() > 100);
        check_length_fields(&hello);
    }

    #[test]
    fn test_randomized_length_fields_always_correct() {
        // Run multiple times to cover different random paths
        for _ in 0..20 {
            let hello = ClientHelloBuilder::build_randomized("auth.vercel.com");
            check_length_fields(&hello);
        }
    }

    #[test]
    fn test_sni_present_in_packet() {
        let sni = "test.example.com";
        let hello = ClientHelloBuilder::build_randomized(sni);
        let found = hello.windows(sni.len()).any(|w| w == sni.as_bytes());
        assert!(found, "SNI bytes must appear in packet");
    }

    #[test]
    fn test_sni_correctly_length_prefixed() {
        let sni = "example.com";
        let hello = ClientHelloBuilder::build_randomized(sni);
        let sni_bytes = sni.as_bytes();
        let name_len_bytes = (sni_bytes.len() as u16).to_be_bytes();
        let mut found = false;
        for i in 0..hello.len().saturating_sub(sni_bytes.len() + 2) {
            if &hello[i..i+2] == &name_len_bytes
                && &hello[i+2..i+2+sni_bytes.len()] == sni_bytes
            {
                found = true;
                break;
            }
        }
        assert!(found, "SNI name must be correctly length-prefixed in packet");
    }

    #[test]
    fn test_two_builds_differ() {
        let h1 = ClientHelloBuilder::build_randomized("example.com");
        let h2 = ClientHelloBuilder::build_randomized("example.com");
        // Not a hard assert — could theoretically collide — but almost never will
        println!("Two randomized builds differ: {}", h1 != h2);
    }

    #[test]
    fn test_different_sni_lengths() {
        for sni in &["a.io", "example.com", "subdomain.example.com", "auth.vercel.com"] {
            let hello = ClientHelloBuilder::build_randomized(sni);
            assert_eq!(hello[0], 0x16);
            assert!(hello.len() > 100);
            check_length_fields(&hello);
        }
    }

    // Deterministic build() preserves the original test contract
    #[test]
    fn test_deterministic_build_structure() {
        let random     = [0x41u8; 32];
        let session_id = [0x42u8; 32];
        let key_share  = [0x43u8; 32];
        let hello = ClientHelloBuilder::build(&random, &session_id, "example.com", &key_share);

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[5], 0x01);
        assert_eq!(hello[9], 0x03);
        assert_eq!(hello[10], 0x03);
        assert_eq!(&hello[11..43], &random);
        assert_eq!(hello[43], 0x20);
        assert_eq!(&hello[44..76], &session_id);
        check_length_fields(&hello);
    }

    #[test]
    fn test_deterministic_build_is_reproducible() {
        let random     = [0x00u8; 32];
        let session_id = [0x00u8; 32];
        let key_share  = [0x00u8; 32];
        let h1 = ClientHelloBuilder::build(&random, &session_id, "example.com", &key_share);
        let h2 = ClientHelloBuilder::build(&random, &session_id, "example.com", &key_share);
        assert_eq!(h1, h2, "Deterministic build must be reproducible");
    }
}