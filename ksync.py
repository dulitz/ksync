#!./pyenv/bin/python

import os, socket
import hashlib, json, subprocess, toml

from datetime import datetime
from pathlib import Path

### config file specifies, for each hostname as returned by socket.gethostname(), a list of roots,
### and a list of prefixes to exclude. may also specify hostmap to override socket.gethostname()
### for filenames and ssh.

### system:
###
### ssh/scp must allow passwordless connection to each host.
###
### "ksync install" uses scp to create ksync.py and .conf in a local user
### directory, and ssh python3 -m venv to create pyenv-ksync in that directory.
### cron runs the .py on the .conf periodically to create a new .ksyncfp fingerprint file
### (either full or incremental). the .ksyncfp file is created as .partial, fingerprinted, compressed,
### and renamed to its completed name which includes the uncompressed fingerprint.
###
### "ksync pull" ssh/scps new fingerprint files (anything lexicographically later than the most recent one)
### from each machine, warning if there is no recent completed one.
###
### "ksync cp" calculates which files to copy from a source machine to a destination machine using
### fingerprint files from the local filesystem.

### development order:
###   1. create full .ksyncfp
###   2. ksync cp including local file optimization, but just calculating, not copying
###   3. create incremental .ksyncfp
###   4. ksync pull
###   5. ksync cp that actually runs rsync or whatever
###   6. ksync install

printonly = False

def scp_toremote(user, host, localsource, remotedest, port=None):
    print('copying %s to %s@%s:%s' % (localsource, user, host, remotedest))
    parg = ['-P%d' % port] if port else []
    if not printonly:
        subprocess.run(['scp'] + parg + [localsource, '%s@%s:%s' % (user, host, remotedest)], check=True)

def ssh(user, host, cmd, tty=False, port=None):
    print('executing ssh %s@%s %s' % (user, host, cmd))
    parg = ['-p%d' % port] if port else []
    if not printonly:
        subprocess.run(['ssh'] + parg + ['-atx' if tty else '-anx', '%s@%s' % (user, host), cmd], check=True)

def confirm(msg):
    print(msg)
    i = input('Type Y or y to persist this change after reboot: ')
    if i.startswith('y') or i.startswith('Y'):
        return
    else:
        raise KeyboardInterrupt


class FileHasher:
    def __init__(self, fname, bufsize=65536*16):
        (self.fname, self.bufsize) = (fname, bufsize)

    def do_hash(self):
        hasher = hashlib.sha256()

        with open(self.fname, 'rb') as f:
            d = f.read(self.bufsize)
            while len(d) > 0:
                hasher.update(d)
                d = f.read(self.bufsize)

        return hasher.hexdigest()
    
###
### fingerprint files are typically named hostname-YYYY-MM-DDTHH:MM:SS[-full].fprint
###
###
### MODE B: write_incremental()
### load JSON
### create map from name to fingerprint
### for each file in the filesystem, recursively:
###   find its mode, nlinks, size, mtime, and ctime
###   if size < SIZE_THRESHOLD, SIZE_THRESHOLD is 0, or if its mode, size, mtime, or ctime changed:
###     calculate its fingerprint
###     append (mode, nlinks, size, mtime, ctime, name, oldhash) to the list associated with that hash
###   delete that name from the JSON map, if it existed
### sort the hashes and write out the data structure as JSON in a timestamped filename
### -- JSON should include the start time of the overall operation and a list of any names remaining
###    in the JSON map ("deleted_names")
###
### MODE C: sync()
### read two JSON files, one for the source and another for the target
### for each fingerprint in the source:
###   if fingerprint exists on the target:
###     if target has every name in source, continue
###     print a cp command to stdout
###   else:
###     print an rsync command to stdout
### for each symlink in the source:
###   if symlink exists on the target:
###     if symlink destination does not match, print a warning
###   else:
###     if linktarget exists on the target, print an ln command to stdout
###     else print a warning
### for each deleted_name, print an echo rm command to stdout

class Snapshot:
    """Loads the most recent snapshot for the specified host.

       If the most recent snapshot is incremental, also loads the snapshots on which it was based.
    """
    
    def __init__(self, host):
        matches = Path('.').glob('%s-20*.ksync' % host)
        if not matches:
            raise Exception('no file %s-20*.ksync in current directory' % host)
        self.stack = []
        self._load(matches[-1])

    def _load(self, fname):
        with open(fname, 'rt') as f:
            j = json.load(f)
            self.stack.append(j)
            based_on = j.get('based_on', '')
            if based_on:
                self._load(based_on)

class Ksync:
    def __init__(self, config, quietmode, hostname):
        (self.config, self.quietmode) = (config, quietmode)
        self.hostname = config.get('hostmap', {}).get(hostname, hostname)

        if 'hosts' not in config:
            raise Exception('config file must have hosts section')
        for h in config['hosts']:
            if self.hostname in h['dns']:
                self.me = h
                break
        else:
            raise Exception('config file must have an entry for %s in hosts section' % self.hostname)

    def _get_workdir(self):
        return self.me.get('working_directory', self.config.get('working_directory', '.'))
    def _get_scpuser(self):
        return self.me.get('scp_user', self.config.get('scp_user', None))

    def install(self, host):
        """ssh to the host and create its working directory if it doesn't exist. copy the config, req.txt,
        and the .py files to the working directory.
        """
        raise Exception('not implemented')

    def _recurse_full(self, path, symlinks, fprints):
        if path.is_symlink():
            s = path.lstat()
            symlinks.append((str(path), os.readlink(path), s.st_mode, s.st_ctime, s.st_mtime))
        elif path.is_file():
            s = path.stat()
            h = FileHasher(path)
            fp = h.do_hash()
            payload = (str(path), s.st_nlink, s.st_mode, s.st_ctime, s.st_mtime)
            existing = fprints.get(fp, None)
            if existing is not None:
                existing.append(payload)
            else:
                fprints[fp] = [payload]
        elif path.is_dir():
            if not self.quietmode:
                print(path)
            for p in path.iterdir():
                self._recurse_full(p, symlinks, fprints)
    
    def write_full(self):
        """For each file in the filesystem, recursively, under roots specified in the config file:
              find its mode, nlinks, size, mtime, and ctime
              if it is a symlink, add (mode, linktarget, mtime, ctime, name) to list of symlinks and continue
              calculate its fingerprint
              append (mode, nlinks, size, mtime, ctime, name) to the list associated with that hash
              sort the hashes and write out the data structure as JSON in a timestamped filename
               -- JSON should include the start time of the overall operation
        """
        volumes = self.me.get('volumes', [])
        if not volumes:
            raise Exception('config file entry for %s in hosts section must have volumes' % self.hostname)

        started = datetime.now().replace(microsecond=0)
        symlinks = []
        fprints = {}
        for volume in volumes:
            self._recurse_full(Path(volume), symlinks, fprints)
        fprintpath = Path(self._get_workdir(), '%s-%s-full.fprint' % (self.hostname, started.isoformat()))
        with fprintpath.open('wt') as fprint:
            fprint.write("""
{
  "started": "%s",
  "function": "SHA-256",
  "symlinks":
""" % (started.isoformat(),))
            json.dump(symlinks, fprint)
            fprint.write(""",
  "fprints":
""")
            json.dump(fprints, fprint, sort_keys=True)
            fprint.write("""
}
""")

    def write_incremental(self, base):
        with open(base, 'rt') as f:
            j = json.load(f)
            raise Exception('not implemented')
            
    def sync(self, source, target):
        with open(source, 'rt') as fsource:
            with open(target, 'rt') as ftarget:
                jsource = json.load(fsource)
                jtarget = json.load(ftarget)
                raise Exception('not implemented')
                ### TODO: write something

def main(argv, quietmode=False, fullmode=False):
    if len(argv) < 3:
        raise Exception('Usage: %s [--quiet] [--full] [install|fprint|pull|cp] configfile [host] ...' % argv[0])
    if argv[1] == '--quiet':
        del argv[1]
        return main(argv, quietmode=True, fullmode=fullmode)
    elif argv[1] == '--full':
        del argv[1]
        return main(argv, quietmode=quietmode, fullmode=True)
    cmd = argv[1]
    config = toml.load(argv[2])
    if not os.environ.get('SSH_AUTH_SOCK', ''):
        raise Exception('SSH_AUTH_SOCK not set -- you should be running ssh-agent')
    ksync = Ksync(config, quietmode, socket.gethostname())
    hosts = config.get('hosts', [])
    if len(argv) <= 3:
        selected = hosts
    else:
        line = { dns : True for dns in argv[3:] }
        selected = []
        for h in hosts:
            assert h.get('dns', None), h
            for n in h['dns']:
                if n in line:
                    selected.append(h)
                    del line[n]
                    continue
        if line:
            raise Exception('hosts %s not found in config' % ' '.join(line.keys()))
    if not selected:
        raise Exception('no hosts specified in config file; nothing to do')
    if cmd == 'install':
        for h in selected:
            ksync.install(h)
    elif cmd == 'fprint':
        if len(argv) > 3:
            raise Exception('fprint runs locally only')
        if fullmode:
            ksync.write_full()
        else:
            ksync.write_incremental()
    elif cmd == 'pull':
        for h in selected:
            ksync.pull(h)
    elif cmd == 'cp':
        raise Exception('not implemented')
    else:
        raise Exception('unknown command %s' % cmd)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))

old_source = """

source=EMPAC
source=KL-disks
#source="KL-disks/Flyhouse Experiments"

target=""
target=""
#target="KL-disks/"

server=northwest
#server=west

tmpfile=rsync-`basename "$source"`.out

nohup rsync -rhv --partial -e 'ssh -p2298' "$source" rsync://daniel@"$server".epispace.com/klnas/"$target" >>/tmp/"$tmpfile"

"""
