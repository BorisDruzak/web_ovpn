"""Exercise the published link task with inherited root-owned desktop links."""
import json
import shutil
import subprocess
import sys

import pytest
import yaml

from test_component_ansible_runtime import ansible_runtime
from test_component_catalog import project


@pytest.mark.parametrize('network_target_exists', [False, True])
def test_existing_desktop_links_belong_to_employee_without_chowning_targets(ansible_runtime, tmp_path, network_target_exists):
    fakeroot = shutil.which('fakeroot')
    if not fakeroot:
        pytest.skip('fakeroot is required for distinct inherited and employee owners')
    executable, project, env = ansible_runtime
    role = yaml.safe_load((project/'roles/desktop_shortcuts/tasks/main.yml').read_text())
    task = next(t for t in role if t.get('name') == 'Create folder links in existing domain test user desktop')
    home = tmp_path/'employee'
    links = [{'name':'Network folder','src':'../net.drives/Public'}, {'name':'Home folder','src':'..'}]
    play = project/'playbooks/synthetic-inherited-shortcut-links.yml'
    play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,
        'vars':{'desktop_shortcuts_user_fields':['employee','x','21000','21001','',''+str(home),'/bin/bash'],
                'desktop_shortcuts_user_desktop_name':'Desktop','desktop_shortcuts_relative_links':links,
                'desktop_shortcuts_user_home':{'stat':{'exists':True}}}, 'tasks':[task]}]))
    code = r'''
import json,os,pathlib,subprocess,sys
home=pathlib.Path(sys.argv[1]); desktop=home/'Desktop';desktop.mkdir(parents=True)
os.chown(home,21000,21001);os.chown(desktop,21000,21001)
network=home/'net.drives/Public'
if sys.argv[2]=='true':
 network.mkdir(parents=True);os.chown(network,22000,22001)
links=json.loads(sys.argv[3])
for link in links:
 path=desktop/link['name'];path.symlink_to(link['src']);assert path.lstat().st_uid==0
command=json.loads(sys.argv[4])
first=subprocess.run(command,capture_output=True,text=True,timeout=30)
assert first.returncode==0,first.stdout+first.stderr
for link in links:
 path=desktop/link['name'];info=path.lstat()
 assert (info.st_uid,info.st_gid)==(21000,21001),'inherited symlink owner was not corrected'
 assert os.readlink(path)==link['src']
assert (home.stat().st_uid,home.stat().st_gid)==(21000,21001)
if network.exists():assert (network.stat().st_uid,network.stat().st_gid)==(22000,22001),'link target owner changed'
second=subprocess.run(command,capture_output=True,text=True,timeout=30)
assert second.returncode==0 and 'changed=0' in second.stdout,second.stdout+second.stderr
print('employee link owners verified; targets unchanged; second run no-op')
'''
    command = [str(executable),'-i','localhost,','-e',json.dumps({'ansible_connection':'local',
        'ansible_become':False,'ansible_python_interpreter':sys.executable}),str(play)]
    result = subprocess.run([fakeroot,sys.executable,'-c',code,str(home),
        'true' if network_target_exists else 'false',json.dumps(links),json.dumps(command)],
        cwd=project,env=env,text=True,capture_output=True,timeout=75)
    assert result.returncode==0,result.stdout+result.stderr
    assert 'second run no-op' in result.stdout
