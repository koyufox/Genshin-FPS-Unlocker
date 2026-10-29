use super::*;
use std::os::unix::net::UnixStream;

#[test]
fn final_report_handoff() {
    for (cleanup_failed, accepted) in [(false, true), (true, true), (false, false)] {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let report = FinalReport(ReportMap::create(sender.as_raw_fd()).unwrap());
        let map = ReportMap::receive(receiver.as_raw_fd()).unwrap();
        drop((sender, receiver));
        let reader = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let received = loop {
                if let Some(record) = map.read().unwrap() {
                    break record;
                }
                assert!(Instant::now() < deadline, "Final report was not published");
                std::thread::sleep(Duration::from_millis(1));
            };
            map.acknowledge(accepted);
            received
        });
        let mut record = Record::new(
            Session::default(),
            Config {
                enabled: true,
                revision: 1,
            },
        );
        record.written = true;
        record.restored = !cleanup_failed;
        if cleanup_failed {
            record.cleanup = Some(Error::new("PAGE_PROTECTION_RESTORE_FAILED", "Test failure"));
        }
        let result = report.publish(&mut record);
        assert_eq!(result.is_ok(), accepted);
        let received = reader.join().unwrap();
        assert_eq!(received.sequence, 2);
        assert_eq!(
            received.state,
            if cleanup_failed { "failed" } else { "patched" }
        );
        assert!(received.written);
        assert_eq!(received.restored, !cleanup_failed);
        assert_eq!(received.cleanup, record.cleanup);
        assert_eq!(received.config, record.config);
    }
}

#[test]
fn shared_state_lifecycle() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "genshin-state-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store = state::Store::initialize(&root).unwrap();
    let initial = store.config().unwrap();
    assert!(initial.enabled);
    assert_eq!(initial.revision, 1);
    let module = root.join("module");
    fs::create_dir(&module).unwrap();
    fs::write(module.join("module.prop"), "id=test\ndescription=old\n").unwrap();
    store.publish_status(&module).unwrap();
    let mut failure = Record::new(
        Session {
            boot: state::boot_id(),
            pid: std::process::id(),
            uid: unsafe { libc::getuid() },
            start: state::process_start(std::process::id()),
        },
        initial,
    );
    failure.fail(
        "load_observation",
        Error::new("TEST_FAILURE", "Test failure"),
    );
    store.save(&failure).unwrap();
    failure.sequence = 2;
    store.save(&failure).unwrap();
    assert!(store.save(&failure).is_err());
    assert!(!store.toggle().unwrap().enabled);
    store.publish_status(&module).unwrap();
    assert_eq!(
        fs::read_to_string(module.join("module.prop")).unwrap(),
        "id=test\ndescription=Status: disabled | Inject failed(1)\n"
    );
    drop(store);
    let mut workers: Vec<_> = (0..4)
        .map(|_| {
            let root = root.clone();
            let module = module.clone();
            std::thread::spawn(move || {
                for _ in 0..2 {
                    let store = state::Store::open(&root).unwrap();
                    store.toggle().unwrap();
                    store.publish_status(&module).unwrap();
                }
            })
        })
        .collect();
    let report_root = root.clone();
    workers.push(std::thread::spawn(move || {
        for sequence in 3..=4 {
            failure.sequence = sequence;
            state::Store::open(&report_root)
                .unwrap()
                .save(&failure)
                .unwrap();
        }
    }));
    for worker in workers {
        worker.join().unwrap();
    }
    let store = state::Store::open(&root).unwrap();
    assert_eq!(
        store.config().unwrap(),
        Config {
            enabled: false,
            revision: 10
        }
    );
    assert!(fs::read_to_string(module.join("module.prop"))
        .unwrap()
        .ends_with("description=Status: disabled | Inject failed(1)\n"));
    let confirmed = fs::read(root.join("config")).unwrap();
    for invalid in [
        "schema=1\nenabled=1\nrevision=01\n",
        "schema=1\nenabled=1\nrevision=9223372036854775808\n",
        "schema=1\nenabled=1\nrevision=1",
        "schema=1\nenabled=1\nrevision=1\nextra=1\n",
    ] {
        fs::write(root.join("config"), invalid).unwrap();
        assert!(store.toggle().is_err());
        assert_eq!(fs::read_to_string(root.join("config")).unwrap(), invalid);
    }
    fs::write(root.join("config"), confirmed).unwrap();
    fs::write(root.join("failures"), "previous-boot\n1:1\n").unwrap();
    store.publish_status(&module).unwrap();
    assert!(fs::read_to_string(module.join("module.prop"))
        .unwrap()
        .ends_with("description=Status: disabled\n"));
    for (path, mode) in [
        (root.join("config"), 0o600),
        (module.join("module.prop"), 0o644),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            mode
        );
    }
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
