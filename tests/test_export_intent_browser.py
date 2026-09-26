import shutil
import subprocess

import pytest


def test_history_restoration_rotates_export_intent_without_changing_submitted_body():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node unavailable')
    code = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const windowEvents={},documentEvents={};
const field={value:'a'.repeat(32)}, form={querySelector:()=>field};
const submittedBody={operation_key:field.value};
let count=0;
const context={window:{addEventListener:(name,fn)=>windowEvents[name]=fn},
document:{addEventListener:(name,fn)=>documentEvents[name]=fn,querySelectorAll:()=>[form]},
crypto:{getRandomValues:array=>array.fill(++count)},Uint8Array};
vm.runInNewContext(fs.readFileSync('app/static/panel-operations.js','utf8'),context);
windowEvents.pageshow({persisted:false});
assert.notEqual(field.value,submittedBody.operation_key);
const firstDisplayKey=field.value;
windowEvents.pageshow({persisted:true});
assert.notEqual(field.value,submittedBody.operation_key);
assert.notEqual(field.value,firstDisplayKey);
assert.equal(submittedBody.operation_key,'a'.repeat(32));
assert.match(field.value,/^[0-9a-f]{32}$/);
'''
    subprocess.run([node,'-e',code],capture_output=True,text=True,check=True)
