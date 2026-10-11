#!/usr/bin/env python3
"""Native held-FD custody and bounded public observation regressions; no live services."""
import contextlib
import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

PATH=Path(__file__).resolve().parents[1]/'taira_signer_observation.py'
spec=importlib.util.spec_from_file_location('signer_observation',PATH)
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
NATIVE=Path('/usr/bin/sha256sum') if Path('/usr/bin/sha256sum').exists() else Path('/sbin/sha256sum')

class Node:
    port=1
    def __init__(self):self.identities=0
    def assert_identity(self):self.identities+=1

class NativeHashTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=PATH.parent)
        self.root=Path(self.temp.name);self.path=self.root/'private.toml'
        self.body=b'[public]\nvalue = "SYNTHETIC_PRIVATE_FIXTURE"\n'
        self.path.write_bytes(self.body);self.path.chmod(0o600)
        self.hash=hashlib.sha256(self.body).hexdigest()
        self.native=mock.patch.object(s,'NATIVE_HASH',NATIVE);self.native.start()
    def tearDown(self):self.native.stop();self.temp.cleanup()
    def check(self):return s.native_config_identity(self.path,self.hash,time.monotonic()+5)
    def test_actual_native_stdin_hash_never_reads_config_in_python(self):
        original_read=os.read;original_pread=os.pread
        inode=self.path.stat().st_ino
        def read(fd,*args):
            self.assertNotEqual(os.fstat(fd).st_ino,inode,'Python read private configuration')
            return original_read(fd,*args)
        def pread(fd,*args):
            self.assertNotEqual(os.fstat(fd).st_ino,inode,'Python pread private configuration')
            return original_pread(fd,*args)
        original_run=subprocess.run;seen=[]
        def run(argv,**kwargs):
            seen.append((argv,kwargs));self.assertEqual(os.fstat(kwargs['stdin']).st_ino,inode)
            self.assertEqual(os.lseek(kwargs['stdin'],0,os.SEEK_CUR),0)
            return original_run(argv,**kwargs)
        with mock.patch.object(os,'read',side_effect=read),mock.patch.object(os,'pread',side_effect=pread),mock.patch.object(subprocess,'run',side_effect=run):
            result=self.check()
        self.assertEqual(result,s._stamp(self.path.stat()))
        self.assertEqual(seen[0][0],[str(NATIVE)])
        self.assertEqual(seen[0][1]['stderr'],subprocess.DEVNULL)
        self.assertEqual(seen[0][1]['env'],{'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    def test_wrong_hash_rejects_without_private_output(self):
        self.hash='0'*64
        with self.assertRaisesRegex(s.SignerObservationError,'^native config digest differs$'):
            self.check()
    def test_content_mutation_after_native_digest_rejects(self):
        original=subprocess.run
        def run(*args,**kwargs):
            value=original(*args,**kwargs);self.path.write_bytes(b'changed private fixture');return value
        with mock.patch.object(subprocess,'run',side_effect=run):
            with self.assertRaisesRegex(s.SignerObservationError,'private config identity changed'):self.check()
    def test_path_replacement_after_native_digest_rejects(self):
        original=subprocess.run
        def run(*args,**kwargs):
            value=original(*args,**kwargs);self.path.unlink();self.path.write_bytes(self.body);self.path.chmod(0o600);return value
        with mock.patch.object(subprocess,'run',side_effect=run):
            with self.assertRaisesRegex(s.SignerObservationError,'private config identity changed'):self.check()
    def test_symlink_hardlink_and_mode_reject_before_hash(self):
        for fault in ('symlink','hardlink','mode'):
            with self.subTest(fault=fault):
                if fault=='symlink':self.path.rename(self.root/'retained');self.path.symlink_to(self.root/'retained')
                elif fault=='hardlink':os.link(self.path,self.root/'extra')
                else:self.path.chmod(0o644)
                with mock.patch.object(subprocess,'run',side_effect=AssertionError('native hash must not run')):
                    with self.assertRaises(s.SignerObservationError):self.check()
                if fault=='symlink':self.path.unlink();(self.root/'retained').rename(self.path)
                elif fault=='hardlink':(self.root/'extra').unlink()
    def test_native_timeout_is_redacted(self):
        with mock.patch.object(subprocess,'run',side_effect=subprocess.TimeoutExpired('PRIVATE_CONTENT',1)):
            with self.assertRaisesRegex(s.SignerObservationError,'^native config observation failed$'):self.check()

class ProfileTests(unittest.TestCase):
    def test_closed_subclass_never_calls_original_config_reader(self):
        class Base:
            def __init__(self,binding):self.config_path=binding['config_path'];self.config_sha256=binding['config_sha256']
            def _configs(self):raise AssertionError('old private reader')
            def assert_identity(self):return self._configs()
        binding={'config_path':'/config','config_sha256':'a'*64,'config_files':[{'path':'/config','sha256':'a'*64}],'launch_selector':{'path':'/current','target':'/release'}}
        with mock.patch.object(os,'geteuid',return_value=0),mock.patch.object(s,'native_config_identity',return_value=('metadata',)):
            node=s._node(Base,binding,time.monotonic()+5)
            self.assertEqual(node.assert_identity(),(('/config',('a'*64,('metadata',))),))
    def test_extended_inventory_rejects_without_constructing_publisher(self):
        binding={'config_path':'/config','config_sha256':'a'*64,'config_files':[{'path':'/config','sha256':'a'*64},{'path':'/extends','sha256':'b'*64}],'launch_selector':{}}
        with mock.patch.object(os,'geteuid',return_value=0):
            with self.assertRaisesRegex(s.SignerObservationError,'single flat config'):s._node(mock.Mock(side_effect=AssertionError('base constructed')),binding,time.monotonic()+5)

class HttpTests(unittest.TestCase):
    @contextlib.contextmanager
    def server(self, status=200, body=b'{"ok":true}', chunked=False):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status);self.send_header('Content-Type','application/json')
                if chunked:self.send_header('Transfer-Encoding','chunked')
                else:self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                if chunked:self.wfile.write(('%x\r\n'%len(body)).encode()+body+b'\r\n0\r\n\r\n')
                else:self.wfile.write(body)
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            node=Node();node.port=server.server_port;yield node
        finally:server.shutdown();server.server_close();thread.join()
    def test_real_content_length_success_and_identity_recheck(self):
        with self.server() as node:
            self.assertEqual(s._get(node,'/status/blocks',{},time.monotonic()+5),{'ok':True})
            self.assertEqual(node.identities,2)
    def test_real_chunked_success_after_terminal_chunk(self):
        with self.server(body=b'17',chunked=True) as node:self.assertEqual(s._get(node,'/status/blocks',{},time.monotonic()+5),17)
    def test_http_errors_recheck_identity_and_retry_only_allowlist(self):
        for code in (404,500,503,401,403,429):
            with self.subTest(code=code),self.server(status=code) as node:
                expected=s._Retryable if code in (404,500,503) else s.SignerObservationError
                with self.assertRaises(expected) as caught:s._get(node,'/status/blocks',{},time.monotonic()+5)
                if code not in (404,500,503):self.assertNotIsInstance(caught.exception,s._Retryable)
                self.assertEqual(node.identities,2)
    def test_early_http_failure_closes_detached_response(self):
        original=http.client.HTTPConnection.getresponse;responses=[]
        def getresponse(connection):
            value=original(connection);responses.append(value);return value
        with self.server(status=503) as node,mock.patch.object(http.client.HTTPConnection,'getresponse',new=getresponse):
            with self.assertRaises(s._Retryable):s._get(node,'/status/blocks',{},time.monotonic()+5)
        self.assertEqual(len(responses),1);self.assertTrue(responses[0].isclosed())
        self.assertEqual(node.identities,2)
    def test_bad_200_json_is_terminal_and_rechecks_identity(self):
        with self.server(body=b'{"duplicate":1,"duplicate":2}') as node:
            with self.assertRaises(s.SignerObservationError) as caught:s._get(node,'/status/blocks',{},time.monotonic()+5)
            self.assertNotIsInstance(caught.exception,s._Retryable);self.assertEqual(node.identities,2)
    def test_slow_response_headers_obey_absolute_socket_deadline(self):
        stopped=threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    for _ in range(200):
                        self.wfile.write(b'x');self.wfile.flush();time.sleep(0.01)
                except (BrokenPipeError,ConnectionResetError):pass
                finally:stopped.set()
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        node=Node();node.port=server.server_port;started=time.monotonic()
        try:
            with mock.patch.object(s,'REQUEST_SECONDS',0.08):
                with self.assertRaises(s.SignerObservationError):s._get(node,'/status/blocks',{},time.monotonic()+5)
            self.assertLess(time.monotonic()-started,0.8)
            self.assertEqual(node.identities,2)
            self.assertTrue(stopped.wait(0.5))
        finally:server.shutdown();server.server_close();thread.join()
    def test_failed_transport_cannot_hide_identity_drift(self):
        node=Node();node.assert_identity=mock.Mock(side_effect=[None,RuntimeError('PRIVATE')])
        with mock.patch.object(http.client.HTTPConnection,'request',side_effect=ConnectionResetError('PRIVATE')):
            with self.assertRaisesRegex(s.SignerObservationError,'^bound local validator identity changed$'):s._get(node,'/status/blocks',{},time.monotonic()+5)

class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.node=Node();self.row={'peer_id':'peer',**{n:'a'*64 for n in ('node_fingerprint','build_fingerprint','config_fingerprint')}}
        self.network='hash:'+'B'*64+'#0000';self.paths=[];self.challenges=[]
        self.patch=mock.patch.object(s,'_node',return_value=self.node);self.patch.start()
    def tearDown(self):self.patch.stop()
    def response(self,node,path,headers,deadline):
        self.paths.append(path)
        if path=='/status/blocks':return 12
        challenge=bytes.fromhex(headers['x-iroha-finality-challenge']).hex().upper();self.challenges.append(challenge)
        status={'protocol_version':4,'restart_required':False,'last_committed_height':12,**{n:'hash:'+'A'*64+'#0000' for n in ('node_fingerprint','build_fingerprint','config_fingerprint')}}
        return {'body':{'version':1,'challenge':challenge,'network_id':self.network,'node_id':'peer','genesis_block_hash':self.network,'status':status,'genesis_finality_proof':{},'finality_proof':{}}}
    def observe(self):return s.observe_attested_status(Node,{},self.row,self.network,'b'*64)
    def test_status_is_derived_only_from_fresh_challenge_attestation(self):
        challenge=bytes(range(32))
        with mock.patch.object(s,'_get',side_effect=self.response),mock.patch.object(s.secrets,'token_bytes',return_value=challenge):node,status,attestation=self.observe()
        self.assertIs(node,self.node);self.assertIs(status,attestation['body']['status']);self.assertEqual(self.paths,['/status/blocks','/v1/bridge/finality/attestation/12'])
        self.assertEqual(attestation['body']['challenge'],'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
    def test_only_canonical_exact_challenge_is_accepted(self):
        challenge=bytes(range(32));canonical=challenge.hex().upper()
        for value in (list(challenge),canonical.lower(),canonical[:-1],canonical+'00','G'*64,'F'*64):
            def get(*args):
                result=self.response(*args)
                if isinstance(result,dict):result['body']['challenge']=value
                return result
            with self.subTest(value=value),mock.patch.object(s,'_get',side_effect=get) as call,mock.patch.object(s.secrets,'token_bytes',return_value=challenge):
                with self.assertRaisesRegex(s.SignerObservationError,'^attestation identity differs$'):self.observe()
                self.assertEqual(call.call_count,2)
    def test_transient_retry_restarts_height_and_fresh_challenge(self):
        failed=[]
        def get(*args):
            result=self.response(*args)
            if 'attestation' in args[1] and not failed:failed.append(True);raise s._Retryable('temporary')
            return result
        with mock.patch.object(s,'_get',side_effect=get):self.observe()
        self.assertEqual(self.paths.count('/status/blocks'),2);self.assertNotEqual(*self.challenges)
    def test_retry_exhausts_exactly_three_attempts(self):
        with mock.patch.object(s,'_get',side_effect=s._Retryable('temporary')) as get:
            with self.assertRaisesRegex(s.SignerObservationError,'retries exhausted'):self.observe()
        self.assertEqual(get.call_count,3)
    def test_bad_height_and_generic_200_do_not_retry(self):
        for value in (True,0,{'status':'ok'},18446744073709551616):
            with self.subTest(value=value),mock.patch.object(s,'_get',return_value=value) as get:
                with self.assertRaises(s.SignerObservationError):self.observe()
                self.assertEqual(get.call_count,1)
    def test_mismatched_attestation_is_terminal(self):
        for field,value in [('challenge',[True]*32),('node_id','other'),('status',{}),('genesis_block_hash','wrong')]:
            def get(*args):
                result=self.response(*args)
                if isinstance(result,dict):result['body'][field]=value
                return result
            with self.subTest(field=field),mock.patch.object(s,'_get',side_effect=get) as call:
                with self.assertRaises(s.SignerObservationError):self.observe()
                self.assertEqual(call.call_count,2)
    def test_zero_challenge_fails_before_attestation_request(self):
        with mock.patch.object(s,'_get',return_value=12) as get,mock.patch.object(s.secrets,'token_bytes',return_value=bytes(32)):
            with self.assertRaisesRegex(s.SignerObservationError,'generated challenge'):self.observe()
            self.assertEqual(get.call_count,1)
    def test_total_deadline_prevents_another_attempt(self):
        with mock.patch.object(s,'_get',side_effect=s._Retryable('temporary')) as get,mock.patch.object(s.time,'monotonic',side_effect=[0,31]):
            with self.assertRaisesRegex(s.SignerObservationError,'deadline'):self.observe()
            self.assertEqual(get.call_count,1)

if __name__=='__main__':unittest.main()
