// BONEMESH_KEYLOG emitter over real loopback nodes (security.md §8). Its own
// test binary so the process-wide env var cannot bleed into other tests. Both
// ends write their directional transport keys; because the role→direction
// mapping is correct, the two ends agree on the I2R key, the R2I key, and the
// transcript-hash label — proof the emitted keys are the real shared session
// keys.
use std::time::{Duration, Instant};

use bonemesh::node::{Config, Node};
use bonemesh::{cert, crypto};

const MESH: &str = "acme-prod";
const NOW: i64 = 1_788_600_000;

fn config(root_priv: &[u8; 32], root_pub: &[u8], label: &str) -> Config {
    let (pub_key, priv_seed) = crypto::mldsa65_generate();
    let c = cert::sign(cert::build(MESH, label, &pub_key, NOW - 100, NOW + 100_000), root_priv);
    Config {
        label: label.to_string(),
        mesh: MESH.to_string(),
        root_public: root_pub.to_vec(),
        cert: c,
        id_private: priv_seed,
    }
}

// dir -> set of (th, key) seen at epoch 0.
fn parse(path: &str) -> std::collections::HashMap<String, Vec<(String, String)>> {
    let mut out: std::collections::HashMap<String, Vec<(String, String)>> = Default::default();
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    for ln in raw.lines() {
        let f: Vec<&str> = ln.split_whitespace().collect();
        if f.len() != 3 || !f[0].ends_with("_TRAFFIC_0") {
            continue;
        }
        let dir = f[0].trim_start_matches("BMX3_").trim_end_matches("_TRAFFIC_0").to_string();
        out.entry(dir).or_default().push((f[1].to_string(), f[2].to_string()));
    }
    out
}

#[test]
fn keylog_emits_agreeing_directional_keys() {
    let path = std::env::temp_dir()
        .join("bonemesh_keylog_test.klog")
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&path);
    std::env::set_var("BONEMESH_KEYLOG", &path);

    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    alpha.connect("127.0.0.1", beta.port()).unwrap();

    // Wait for both ends to write their epoch-0 entries (4 lines total).
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let n = std::fs::read_to_string(&path).unwrap_or_default().lines().count();
        if n >= 4 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let by_dir = parse(&path);
    for dir in ["I2R", "R2I"] {
        let entries = by_dir.get(dir).unwrap_or_else(|| panic!("no {dir} entries"));
        assert!(entries.len() >= 2, "{dir}: both ends should have written it, got {}", entries.len());
        let key0 = &entries[0].1;
        assert_eq!(key0.len(), 64, "{dir} key is not a 32-byte hex value: {key0}");
        for e in entries {
            assert_eq!(&e.1, key0, "{dir} key disagrees between ends (role→direction mapping wrong)");
            assert_eq!(e.0, entries[0].0, "{dir} transcript-hash disagrees between ends");
        }
    }
    assert_ne!(by_dir["I2R"][0].1, by_dir["R2I"][0].1, "I2R and R2I keys are identical");

    std::env::remove_var("BONEMESH_KEYLOG");
    let _ = std::fs::remove_file(&path);
    alpha.kill();
    beta.kill();
}
