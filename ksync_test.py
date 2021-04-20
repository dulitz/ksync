import time
import ksync

config = {
    'working_directory': '.',
    'hosts': [
        {
            'dns': ['test'],
            'volumes': ['../ksync']
            }
        ]
    }
ks = ksync.Ksync(config, quietmode=False, hostname='test')
ks.write_full()
basesnap = ksync.Snapshot(config['hosts'][0])

time.sleep(1)

ks.write_incremental()
snap = ksync.Snapshot(config['hosts'][0])

for (fp, flist) in snap.items():
    print(fp, flist)
