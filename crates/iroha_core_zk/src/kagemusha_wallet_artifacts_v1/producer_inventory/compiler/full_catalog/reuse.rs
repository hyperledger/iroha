//! Inactive, untrusted engineering original intake; never an installed-source resume.

use super::*;

/// Validate every supplied content address before linking any candidate original
/// into this new run. A link transports bytes only; compiler indexing and complete
/// current-source import remain mandatory after this function returns.
fn collect(root: &Path) -> Result<Vec<OriginalV1>, Error> {
    regular_directory(root)?;
    let mut blobs = BTreeMap::new();
    let mut descriptors = BTreeMap::new();
    let mut keys = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| Error::Inventory)? {
        if blobs.len() >= ARTIFACT_MAX_COUNT_V1 * 3 {
            return Err(Error::Inventory);
        }
        let entry = entry.map_err(|_| Error::Inventory)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::Inventory)?;
        let hash: [u8; 32] = hex::decode(&name)
            .map_err(|_| Error::Inventory)?
            .try_into()
            .map_err(|_| Error::Inventory)?;
        if name != hex::encode(hash) {
            return Err(Error::Inventory);
        }
        let bytes = pinned_file(&entry.path(), PROVING_KEY_MAX_BYTES_V1, hash)?;
        let blob = BlobV1::of(&bytes);
        if blobs.insert(hash, blob).is_some() {
            return Err(Error::Inventory);
        }
        if bytes.starts_with(b"PIPAPK01") {
            if bytes.len() < 44 || keys.len() >= ARTIFACT_MAX_COUNT_V1 {
                return Err(Error::Inventory);
            }
            let binding: [u8; 32] = bytes[8..40].try_into().map_err(|_| Error::Inventory)?;
            let length = u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| Error::Inventory)?)
                as usize;
            if length == 0 || length > VERIFYING_KEY_MAX_BYTES_V1 {
                return Err(Error::Inventory);
            }
            let vk = bytes.get(44..44 + length).ok_or(Error::Inventory)?;
            keys.push((binding, BlobV1::of(vk), blob));
        } else if bytes.len() <= DESCRIPTOR_MAX_BYTES_V1
            && let Ok(binding) = DescriptorBinding::decode_v2(&bytes)
            && descriptors
                .insert(*binding.digest(), blob)
                .is_some_and(|old| old != blob)
        {
            return Err(Error::Inventory);
        }
    }
    if keys.is_empty() {
        return Err(Error::Inventory);
    }
    keys.into_iter()
        .map(|(binding, verifying_key, proving_key)| {
            if blobs.get(&verifying_key.sha256) != Some(&verifying_key) {
                return Err(Error::Inventory);
            }
            let original = OriginalV1 {
                descriptor: *descriptors.get(&binding).ok_or(Error::Inventory)?,
                verifying_key,
                proving_key,
            };
            original.validate()?;
            Ok(original)
        })
        .collect()
}

pub(super) fn intake(output: &mut Originals) -> Result<Vec<OriginalV1>, Error> {
    let Some(manifest) = std::env::var_os("KAGEMUSHA_WALLET_REUSE_INPUTS") else {
        return Ok(Vec::new());
    };
    let bytes = bounded_file(Path::new(&manifest), 16_384)?;
    let roots: Vec<String> = norito::json::from_slice(&bytes).map_err(|_| Error::Inventory)?;
    if roots.is_empty() || roots.len() > 4 {
        return Err(Error::Inventory);
    }
    publish(
        &output
            .root
            .parent()
            .ok_or(Error::Inventory)?
            .join("reuse-inputs.json"),
        &bytes,
    )?;
    let mut selected = BTreeMap::new();
    for root in roots {
        let root = Path::new(&root);
        // This engineering surface accepts only explicit inactive input folders.
        // It never opens a live StreamingCatalog or acquires its owner/lock.
        if !root.is_absolute() || root == output.root {
            return Err(Error::Inventory);
        }
        let records = collect(root)?;
        for original in records {
            if selected
                .insert(original.proving_key.sha256, original)
                .is_some_and(|old| old != original)
            {
                return Err(Error::Inventory);
            }
            if selected.len() > ARTIFACT_MAX_COUNT_V1 {
                return Err(Error::Inventory);
            }
            for blob in [
                original.descriptor,
                original.verifying_key,
                original.proving_key,
            ] {
                let target = output.root.join(hex::encode(blob.sha256));
                if target.try_exists().map_err(|_| Error::Unavailable)? {
                    drop(pinned_file(
                        &target,
                        blob.length(PROVING_KEY_MAX_BYTES_V1)?,
                        blob.sha256,
                    )?);
                    continue;
                }
                let total = output
                    .bytes
                    .checked_add(blob.bytes)
                    .filter(|total| *total <= OUTPUT_BYTES)
                    .ok_or(Error::Inventory)?;
                let source = root.join(hex::encode(blob.sha256));
                // Recheck the source after the scan and the resulting link after
                // publication. Complete source import rechecks all bytes again.
                drop(pinned_file(
                    &source,
                    blob.length(PROVING_KEY_MAX_BYTES_V1)?,
                    blob.sha256,
                )?);
                fs::hard_link(&source, &target).map_err(|_| Error::Unavailable)?;
                drop(pinned_file(
                    &target,
                    blob.length(PROVING_KEY_MAX_BYTES_V1)?,
                    blob.sha256,
                )?);
                output.bytes = total;
                output.count += 1;
            }
        }
    }
    File::open(&output.root)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error::Unavailable)?;
    eprintln!(
        "WALLET_SOURCE_REUSE untrusted_candidates={} linked_originals={} logical_bytes={} selected_sources=0 grant=false",
        selected.len(),
        output.count,
        output.bytes
    );
    Ok(selected.into_values().collect())
}

#[test]
fn reuse_intake_requires_exact_complete_content_addresses() {
    let root = tempfile::tempdir().unwrap();
    assert!(collect(root.path()).is_err());
    fs::write(root.path().join("unaddressed"), b"DATA").unwrap();
    assert!(collect(root.path()).is_err());
    fs::remove_file(root.path().join("unaddressed")).unwrap();
    let body = b"PIPAPK01";
    fs::write(root.path().join(hex::encode(BlobV1::of(body).sha256)), body).unwrap();
    assert!(collect(root.path()).is_err());
    fs::write(
        root.path().join(hex::encode(BlobV1::of(body).sha256)),
        b"changed",
    )
    .unwrap();
    assert!(collect(root.path()).is_err());
}

#[test]
fn reuse_collect_recovers_exact_triplets_and_rejects_missing_metadata() {
    use ff::Field;
    let root = tempfile::tempdir().unwrap();
    let params = PinnedParams::<Ep>::derive(8).unwrap();
    let key = keygen_pk_v2(
        &params,
        &super::super::tests::Tiny(Fq::ONE),
        &config(
            vec![InstanceType::Bounded],
            false,
            super::super::tests::limits(),
        ),
    )
    .unwrap();
    let bodies = [
        key.binding().encoded().to_vec(),
        key.vk().to_bytes().to_vec(),
        key.artifact_bytes_v2().unwrap(),
    ];
    let blobs = bodies.each_ref().map(|bytes| BlobV1::of(bytes));
    for (bytes, blob) in bodies.iter().zip(blobs) {
        fs::write(root.path().join(hex::encode(blob.sha256)), bytes).unwrap();
    }
    assert_eq!(
        collect(root.path()).unwrap(),
        [OriginalV1 {
            descriptor: blobs[0],
            verifying_key: blobs[1],
            proving_key: blobs[2]
        }]
    );
    let descriptor = root.path().join(hex::encode(blobs[0].sha256));
    fs::remove_file(&descriptor).unwrap();
    assert!(collect(root.path()).is_err());
    fs::write(descriptor, &bodies[0]).unwrap();
    fs::remove_file(root.path().join(hex::encode(blobs[1].sha256))).unwrap();
    assert!(collect(root.path()).is_err());
}
