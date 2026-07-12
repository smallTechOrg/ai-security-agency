import subprocess, sys, urllib.request, json
cmds=[['python','-m','compileall','backend/app'],['python','-m','pytest','-q'],['bash','-lc','cd frontend && npm run build']]
for cmd in cmds:
    print('RUN',' '.join(cmd)); r=subprocess.run(cmd); assert r.returncode==0
print('VERIFY_OK')
