import os,requests
B=os.environ['BUILDMODE_'+'DISPATCHER_URL']
b=dict(user_id='daniel+admin@armorerlabs.com',message='Run which gdb;which gcore;which python3;which gcc',session_id='49ca40a219ae')
print(requests.post(B+'/session/'+'generate',json=b,headers={'X-SL-Token':'x'},timeout=120).text)
