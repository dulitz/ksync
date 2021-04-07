
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
