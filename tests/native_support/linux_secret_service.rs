use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

pub(crate) fn assert_disposable() -> PathBuf {
    assert_eq!(
        std::env::var("MAILCTL_SECRET_SERVICE_ACCEPTANCE").as_deref(),
        Ok("1"),
        "native acceptance requires an explicitly disposable Secret Service session"
    );
    assert_eq!(rustix::process::geteuid().as_raw(), 65534);
    assert_eq!(rustix::process::getegid().as_raw(), 65534);
    let root = PathBuf::from(
        std::env::var_os("MAILCTL_SECRET_SERVICE_ROOT").expect("disposable session root"),
    );
    let temporary = fs::canonicalize("/tmp").unwrap();
    assert!(root.is_absolute() && root.starts_with(&temporary) && root != temporary);
    assert_eq!(fs::canonicalize(&root).unwrap(), root);
    private_directory(&root);
    for (name, leaf) in [
        ("HOME", "home"),
        ("XDG_RUNTIME_DIR", "runtime"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_CACHE_HOME", "cache"),
    ] {
        let path = PathBuf::from(std::env::var_os(name).expect("disposable session directory"));
        assert_eq!(path, root.join(leaf));
        assert_eq!(fs::canonicalize(&path).unwrap(), path);
        private_directory(&path);
    }
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").expect("private session bus");
    let path = address
        .strip_prefix("unix:path=")
        .and_then(|value| value.split(',').next())
        .map(PathBuf::from)
        .expect("private Unix session bus");
    assert!(
        !address.contains(';'),
        "only one private session bus is allowed"
    );
    assert_eq!(path, root.join("bus"));
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.uid(), 65534);
    root
}

fn private_directory(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.uid(), 65534);
    assert_eq!(metadata.mode() & 0o777, 0o700);
}
