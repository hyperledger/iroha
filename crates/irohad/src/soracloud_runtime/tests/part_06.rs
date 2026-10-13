#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a root Linux supervisor, installed sealed runtime closure, KVM, and explicit guest-asset paths"]
async fn inrou_portable_smoke_boots_debian_guest_and_serves_healthcheck() -> Result<()> {
    let kernel_image = portable_smoke_required_env_path("IROHA_INROU_PORTABLE_KERNEL_IMAGE")?;
    let rootfs_image = portable_smoke_required_env_path("IROHA_INROU_PORTABLE_ROOTFS_IMAGE")?;
    let initrd_image = std::env::var("IROHA_INROU_PORTABLE_INITRD_IMAGE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    if let Some(initrd_image) = initrd_image.as_ref()
        && !initrd_image.is_file()
    {
        eyre::bail!(
            "IROHA_INROU_PORTABLE_INITRD_IMAGE must point to an existing file, got {}",
            initrd_image.display()
        );
    }
    let python_http_server = "mkdir -p /var/lib/soracloud/volumes/index_state
printf 'booted\n' >/var/lib/soracloud/volumes/index_state/boot-marker
exec python3 /var/lib/soracloud/materialization/bundle/app/inrou-health.py
"
    .to_owned();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let selected_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    let (operator_preseed_store, published_artifact) =
        create_portable_inrou_operator_preseed_artifact(
            &temp_dir,
            selected_guest_isa,
            &kernel_image,
            &rootfs_image,
            initrd_image.as_deref(),
        )?;
    let bundle_bytes = create_inrou_application_bundle_archive_for_linux_test()?;
    let mut bundle = sample_inrou_test_bundle()?;
    bundle.container.args = vec!["-lc".to_owned(), python_http_server];
    bundle.container.bundle_path = "/bundles/inrou-portable-smoke.tgz".to_owned();
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let inrou = bundle.container.inrou.as_mut().expect("inrou manifest");
    inrou
        .guest_images
        .retain(|guest_isa, _| guest_isa == &selected_guest_isa);
    let selected_image = inrou
        .guest_images
        .get_mut(&selected_guest_isa)
        .expect("selected host guest image");
    selected_image.kernel_image_path = format!("/inrou/{}/vmlinux", selected_guest_isa.as_str());
    selected_image.rootfs_image_path =
        format!("/inrou/{}/rootfs.ext4", selected_guest_isa.as_str());
    selected_image.initrd_image_path = initrd_image
        .as_ref()
        .map(|_| format!("/inrou/{}/initrd.img", selected_guest_isa.as_str()));
    selected_image.published_artifact = published_artifact.clone();
    assert_eq!(inrou.guest_images.len(), 1);
    let manifest_digest =
        parse_sorafs_manifest_digest_hex(&published_artifact.manifest_digest_hex)?;
    assert!(
        operator_preseed_store
            .manifest_by_digest(&manifest_digest)
            .is_some()
    );
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle.validate_for_admission()?;
    let mut state = test_state();
    let deployment_state = sample_deployment_state(&bundle);
    let local_peer_id = canonical_inrou_test_peer_id();
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment_state);
    }
    insert_local_inrou_service_placement_fixture(
        &mut state,
        &bundle,
        local_peer_id,
        selected_guest_isa,
    );
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &bundle_bytes,
    )?;
    let mut config = test_runtime_manager_config(temp_dir.path().to_path_buf())
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    config.inrou.trusted_guest_artifact = Some(published_artifact);
    config.inrou.start_grace = Duration::from_secs(240);
    #[cfg(target_os = "linux")]
    let child_identity = portable_vm_child_identity(&config.inrou)?;
    let manager = SoracloudRuntimeManager::new(config, Arc::clone(&state))
        .with_operator_preseed_store(
            Arc::clone(&operator_preseed_store),
            qualified_test_operator_preseed_manifests(&operator_preseed_store),
        )?
        .with_mutation_sink(Arc::new(StartupQualifiedSmokeRuntimeMutationSink::default()));
    let mut supervisor = Supervisor::new();
    let shutdown = supervisor.shutdown_signal();
    let (_handle, child) = manager
        .start(shutdown.clone())
        .wrap_err("start the production-posture Inrou manager with its exact preseed")?;
    supervisor.monitor(child);
    // Keep the root-only smoke environment fail-safe even when an assertion
    // panics: a detached QEMU process under the reserved identity would
    // poison every subsequent qualification attempt on this host.
    let smoke_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        let service_dir = temp_dir
            .path()
            .join("services")
            .join(storage_path_component(bundle.service.service_name.as_ref()))
            .join(storage_path_component(&bundle.service.service_version));
        let runtime_state = read_hosted_http_runtime_state(&service_dir)?
            .ok_or_else(|| eyre::eyre!("started Inrou service has no runtime state"))?;
        assert_eq!(
            runtime_state.health_status,
            SoraServiceHealthStatusV1::Healthy,
            "started Inrou service is not healthy: {:?}",
            runtime_state.last_error
        );
        assert_eq!(runtime_state.replicas.len(), 1);
        let replica = runtime_state
            .replicas
            .first()
            .expect("replica runtime state present");
        assert_eq!(replica.health_status, SoraServiceHealthStatusV1::Healthy);
        assert!(replica.pid.is_some());
        assert!(
            service_dir
                .join("replicas/replica-0001/inrou_cloud_init/meta-data")
                .exists()
        );
        let hydrated_guest_root = service_dir
            .join("replicas/replica-0001/inrou_bundle/inrou")
            .join(selected_guest_isa.as_str());
        assert!(hydrated_guest_root.join("vmlinux").is_file());
        assert!(hydrated_guest_root.join("rootfs.ext4").is_file());
        assert_eq!(
            hydrated_guest_root.join("initrd.img").is_file(),
            initrd_image.is_some()
        );
        let nonselected_guest_isa = match selected_guest_isa {
            SoraInrouGuestIsaV1::X8664 => SoraInrouGuestIsaV1::Aarch64,
            SoraInrouGuestIsaV1::Aarch64 => SoraInrouGuestIsaV1::X8664,
        };
        assert!(
            !service_dir
                .join("replicas/replica-0001/inrou_bundle/inrou")
                .join(nonselected_guest_isa.as_str())
                .exists()
        );
        assert!(
            hosted_http_per_replica_volume_materialization_dir(
                &build_hosted_http_service_volume_dir(
                    temp_dir.path(),
                    "web_portal",
                    "2026.02.0",
                    1,
                    "root_disk",
                ),
                1,
            )
            .join("rootfs.ext4")
            .exists()
        );
        assert!(
            hosted_http_per_replica_volume_materialization_dir(
                &build_hosted_http_service_volume_dir(
                    temp_dir.path(),
                    "web_portal",
                    "2026.02.0",
                    1,
                    "index_state",
                ),
                1,
            )
            .join("lease.raw")
            .exists()
        );
        let listen_base_url = replica
            .listen_base_url
            .as_deref()
            .expect("replica listen base url");
        probe_hosted_http_health(
            listen_base_url,
            bundle.container.lifecycle.healthcheck_path.as_deref(),
        )?;
        let resources = bundle.container.resources;
        let cpu_quota_us = u64::from(resources.cpu_millis.get()) * 100;
        let expected_attestation = format!(
            "schema_version=1\n\
uid=1000\n\
gid=1000\n\
supplementary_gids=\n\
inrou_shell=/usr/sbin/nologin\n\
no_new_privs=1\n\
limit_nofile_soft={}\n\
limit_nofile_hard={}\n\
tasks_max={}\n\
cpu_max={cpu_quota_us} 100000\n\
memory_max={}\n\
memory_swap_max=0\n\
service_mount_type=tmpfs\n\
service_mount_total_bytes={}\n\
service_mount_uid=1000\n\
service_mount_gid=1000\n\
service_mount_mode=0700\n\
service_mount_rw=1\n\
service_mount_nosuid=1\n\
service_mount_nodev=1\n\
service_mount_noexec=1\n\
root_shell=/usr/sbin/nologin\n\
hardening_marker_body=1\n\
hardening_marker_uid=0\n\
hardening_marker_gid=0\n\
hardening_marker_mode=0444\n\
ssh.service_masked=1\n\
ssh.socket_masked=1\n\
sshd.service_masked=1\n\
sshd.socket_masked=1\n\
ssh_port_22_listening=0\n",
            resources.max_open_files_per_process.get(),
            resources.max_open_files_per_process.get(),
            resources.max_tasks.get(),
            resources.memory_bytes.get(),
            resources.ephemeral_storage_bytes.get(),
        );
        assert_eq!(
            fetch_hosted_http_text(listen_base_url, "/attestation-v1")?,
            expected_attestation,
            "the running guest must expose the exact admitted limits and hardening state"
        );
        Ok(())
    }));
    shutdown.send();
    let supervisor_result =
        match tokio::time::timeout(Duration::from_secs(60), supervisor.start()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(eyre::eyre!(
                "Inrou runtime supervisor did not stop cleanly: {error:?}"
            )),
            Err(_) => Err(eyre::eyre!(
                "Inrou runtime supervisor did not stop within its bounded deadline"
            )),
        };
    #[cfg(target_os = "linux")]
    let identity_cleanup_result = (|| -> Result<()> {
        // The worker's bounded path may spend ten seconds issuing QMP
        // powerdown, twenty seconds honoring this fixture's workload grace,
        // and another eleven seconds in forced child/cgroup/log cleanup.
        let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            match ensure_no_process_with_inrou_identity(&child_identity) {
                Ok(()) => return Ok(()),
                Err(_) if std::time::Instant::now() < cleanup_deadline => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(error).wrap_err(
                        "prove the dedicated Inrou identity is vacant after smoke shutdown",
                    );
                }
            }
        }
    })();
    #[cfg(not(target_os = "linux"))]
    let identity_cleanup_result: Result<()> = Ok(());
    match smoke_result {
        Ok(result) => {
            supervisor_result?;
            identity_cleanup_result?;
            result
        }
        Err(panic) => {
            // Shutdown and vacancy checks above are deliberately attempted
            // before preserving the original assertion panic.
            if let Err(error) = supervisor_result {
                iroha_logger::error!(
                    ?error,
                    "Inrou smoke supervisor cleanup also failed after an assertion panic"
                );
            }
            if let Err(error) = identity_cleanup_result {
                iroha_logger::error!(
                    ?error,
                    "Inrou smoke identity cleanup also failed after an assertion panic"
                );
            }
            std::panic::resume_unwind(panic)
        }
    }
}
include!("runtime_tail.rs");
include!("../authoritative_execution_tests.rs");
