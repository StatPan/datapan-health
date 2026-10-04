#!/usr/bin/env python3
"""Local synthetic source and real runtime container proof; no provider requests."""
import collections
import os
import concurrent.futures
import datetime
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
root=Path(__file__).resolve().parent.parent
config=json.loads((root/'config/canaries.json').read_text())
observed=datetime.datetime.now(datetime.timezone.utc).isoformat()
rows=[{'key':c['gatus_endpoint_key'],'results':[{'success':True,'timestamp':observed}]} for c in config['canaries']]
state={'calls':0,'fail':False}
lock=threading.Lock()
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  with lock:state['calls']+=1;fail=state['fail']
  self.send_response(503 if fail else 200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(rows if not fail else {'secret':'must never be public'}).encode())
 def log_message(self,*a):pass
source=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=source.serve_forever,daemon=True).start()
cmd=['docker','run','-d','--read-only','--network','host','--entrypoint','/health-public','-v',str(root/'config')+':/config:ro',os.environ.get('RUNTIME_IMAGE','datapan-health-runtime:test'),'-listen','127.0.0.1:18986','-canaries','/config/canaries.json','-allowed-origins','https://datapan.statpan.com','-gatus-status-url','http://127.0.0.1:'+str(source.server_port)+'/']
cid=subprocess.check_output(cmd).decode().strip()
def get(path='/datapan/v1/dependencies',method='GET',origin='https://datapan.statpan.com'):
 request=urllib.request.Request('http://127.0.0.1:18986'+path,method=method,headers={'Origin':origin,'X-Forwarded-For':'spoofed-client'})
 try:response=urllib.request.urlopen(request,timeout=8)
 except urllib.error.HTTPError as error:response=error
 with response:return response.status,dict(response.headers),response.read().decode()
try:
 for _ in range(30):
  try:seed=get();break
  except OSError:time.sleep(.1)
 assert seed[0]==200
 before=state['calls']
 with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:responses=list(pool.map(lambda _:get(),range(100)))
 counts=collections.Counter(r[0] for r in responses)
 assert counts[429]>0 and counts[200]>0
 assert state['calls']==before
 for code,headers,body in responses:
  if code in (429,503):assert headers.get('Retry-After')=='1' and headers.get('Cache-Control')=='no-store' and headers.get('Access-Control-Allow-Origin')=='https://datapan.statpan.com'
 time.sleep(1.2)
 assert get()[0]==200
 assert get(method='POST')[0]==405
 assert get(path='/datapan/v1/dependencies?operation=any')[0]==404
 assert get(origin='https://evil.example')[0]==403
 state['fail']=True
 time.sleep(5.1)
 failure=get();assert failure[0]==503 and 'secret' not in failure[2]
 failed_calls=state['calls']
 for _ in range(5):assert get()[0]==503
 assert state['calls']==failed_calls
 state['fail']=False
 time.sleep(1.2)
 assert get()[0]==200
 result={'schema_version':'datapan.health-local-access-proof.v1','scope':'local_runtime_container_with_synthetic_private_source','source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root).decode().strip(),'runtime_image_id':subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',os.environ.get('RUNTIME_IMAGE','datapan-health-runtime:test')]).decode().strip(),'burst_responses':dict(counts),'extra_private_fetches_during_100_reads':0,'upstream_failure_http':failure[0],'recovery_http':200,'read_only_and_origin_guards':'passed','result':'passed'}
 output=root/'out/access-proof.json';output.parent.mkdir(exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
finally:
 subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL)
 source.shutdown()
