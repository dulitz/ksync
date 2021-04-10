#!./pyenv/bin/python

import heapq, math, os, socket
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
    localsources = localsource if type(localsource) == type([]) else [localsource]
    parg = ['-P%d' % port] if port else []
    if not printonly:
        subprocess.run(['scp'] + parg + localsources + ['%s@%s:%s' % (user, host, remotedest)], check=True)

def scp_fromremote(user, host, remotesource, localdest, port=None, strictfilenames=True):
    print('copying %s@%s:%s to %s' % (remotesource, user, host, localdest))
    remotesources = remotesource if type(remotesource) == type([]) else [remotesource]
    parg = ['-P%d' % port] if port else []
    targ = [] if strictfilenames else ['-T']
    if not printonly:
        subprocess.run(['scp'] + parg + targ + ['%s@%s:%s' % (user, host, r) for r in remotesources] + [localdest], check=True)

def ssh(user, host, cmd, tty=False, port=None, check=True):
    print('executing ssh %s@%s %s' % (user, host, cmd))
    parg = ['-p%d' % port] if port else []
    if not printonly:
        subprocess.run(['ssh'] + parg + ['-atx' if tty else '-anx', '%s@%s' % (user, host), cmd], check=check)

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
        pattern = '%s-20*.fprint' % host
        matches = Path('.').glob(pattern)
        if not matches:
            raise Exception('no file %s in current directory' % pattern)
        self.stack = []
        self._load(matches[-1])

    def _load(self, fname):
        with open(fname, 'rt') as f:
            j = json.load(f)
            self.stack.append(j)
            based_on = j.get('based_on', '')
            if based_on:
                self._load(based_on)

    def get_volumes(self):
        return self.stack[0]['volumes'] # most recent incremental

    def items(self):
        """returns an iterator over all the (fingerprint, filelist) items"""
        lastfp = None
        for pair in heapq.merge(*self.stack, key=lambda p: p[0]):
            if lastfp != pair[0]:
                lastfp = pair[0]
                yield pair
                

class Ksync:
    def __init__(self, config, quietmode, hostname):
        (self.config, self.quietmode) = (config, quietmode)
        self.hostname = config.get('hostmap', {}).get(hostname, hostname)

        if 'hosts' not in config:
            raise Exception('config must have hosts section')
        self.me = self._gethost(self.hostname, ifnone={})

    def _gethost(self, hostname, ifnone=None):
        for h in self.config['hosts']:
            if hostname in h['dns']:
                return h
        if ifnone is None:
            raise Exception('config must have entry for %s in hosts section' % self.hostname)
        return ifnone
    def _getvar(self, variable, host=None, default=None):
        if host is None:
            host = self.me
        return host.get(variable, self.config.get(variable, default))
    def _ssh_internal(self, host, cmd, tty=False, check=True):
        ssh(self._getvar('scp_user', host=host), host['dns'][0], cmd, tty=tty, check=check)
    def _scp_toremote(self, host, localsources, remotedest):
        scp_toremote(self._getvar('scp_user', host=host), host['dns'][0], localsources, remotedest)
    def _scp_fromremote(self, host, remotesources, localdest):
        scp_fromremote(self._getvar('scp_user', host=host), host['dns'][0], remotesources, localdest, strictfilenames=False)

    def install(self, host, sources):
        """ssh to the host and create its working directory if it doesn't exist. copy the config, req.txt,
        and .py files to the working directory. create venv "pyenv" and pip install -r req.txt
        """
        workdir = self._getvar('working_directory', host, default='.')
        cmd = 'mkdir %s' % workdir
        self._ssh_internal(host, cmd, check=False)
        self._scp_toremote(host, sources, workdir)
        cmd = 'cd "%s" && PATH=/usr/local/bin:"$PATH" python3 -m venv pyenv && pyenv/bin/pip install --upgrade pip && pyenv/bin/pip install -r req.txt' % workdir
        self._ssh_internal(host, cmd)

    def pull(self, host):
        """scp to host to copy its fprint files here.
        """
        remoteworkdir = self._getvar('working_directory', host, default='.')
        self._scp_fromremote(host, '%s/`hostname`-20*.fprint' % remoteworkdir, self._getvar('working_directory'))

    def _recurse_full(self, path, symlinks, fprints):
        if path.is_symlink():
            s = path.lstat()
            symlinks.append((str(path), os.readlink(path), s.st_mode, s.st_ctime, s.st_mtime))
        elif path.is_file():
            s = path.stat()
            h = FileHasher(path)
            fp = h.do_hash()
            payload = (str(path), s.st_size, s.st_nlink, s.st_mode, s.st_ctime, s.st_mtime)
            existing = fprints.get(fp, None)
            if existing is not None:
                existing.append(payload)
            else:
                fprints[fp] = [payload]
        elif path.is_dir():
            if not self.quietmode and path.parts[-1] != '@eaDir':
                print(path)
            try:
                for p in path.iterdir():
                    try:
                        self._recurse_full(p, symlinks, fprints)
                    except PermissionError as e:
                        print('permission denied: %s' % e)
            except PermissionError as e:
                print('permission denied: %s' % e)
    
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
        workdir = self._getvar('working_directory', default='.')
        fprintpath = Path(workdir, '%s-%s-full.fprint' % (self.hostname, started.isoformat()))
        with fprintpath.open('wt') as fprint:
            fprint.write("""
{
  "started": "%s",
  "function": "SHA-256",
  "volumes": %s,
  "symlinks":
""" % (started.isoformat(), json.dumps(volumes)))
            json.dump(sorted(symlinks), fprint)
            fprint.write(""",
  "fprints":
""")
            json.dump(fprints, fprint, sort_keys=True)
            fprint.write("""
}
""")

    def write_incremental(self, base=None):
        if base is None:
            # use the most recent fprint
            raise Exception('not implemented')
        with open(base, 'rt') as f:
            j = json.load(f)
            raise Exception('not implemented')
            
    def sync(self, source, target):
        """collect every filelist in target with length > 1.
        determine whether any directories contain only such duplicated files.
        if the smallest number of hardlinks equals the length of the list, ...
        otherwise ...

        for every source volume that does not match a target volume, count the number of
        files/bytes in it and print an "ignoring" line.

        collect the filelist for every fprint in source that is not in target but is in
        a source volume that matches a target volume. copy it to the first matching volume.
        warn if pre-existing target file is newer or longer. show pre-existing versus not.
        

        given a filelist, a source volume, a target volume, and a predicate, group them 

        symlinks ...
        """
        srchost = self._gethost(source)
        targhost = self._gethost(target)
        src = Snapshot(source)
        targ = Snapshot(target)
        targvolumes = {}
        srcmatchprefixes = {}
        targmatchprefixes = {}
        for v in targ.get_volumes():
            p = Path(v).name
            if targvolumes.has_key(p):
                raise Exception('target %s has duplicate volumes for %s: %s' % (target, p, repr(targ.get_volumes())))
            targvolumes[p] = v
        (nvolumes, nfiles, nbytes) = (0, 0, 0)
        for v in src.get_volumes():
            targprefix = targvolumes.get(Path(v).name, None)
            if targprefix:
                if srcmatchprefixes.has_key(v):
                    raise Exception('source %s has two paths for volume %s: %s' % (source, v, repr(src.get_volumes())))
                srcmatchprefixes[v] = targprefix
                assert not targprefix in targmatchprefixes, (targprefix, targmatchprefixes)
                targmatchprefixes[targprefix] = v
            else:
                nvolumes += 1
        def matches(prefix, payloads):
            for p in payloads:
                if p[0].startswith(prefix):
                    return True
            return False
        for (fprint, payloadlist) in src.items():
            for prefix in srcmatchprefixes:
                if matches(prefix, payloadlist):
                    break
            else:
                nfiles += 1
                nbytes += payloadlist[0][1]
        if not self.quietmode:
            if nfiles or nvolumes or nbytes:
                print('ignoring %d source volumes (%d files in %d MB) not in target' % (nvolumes, nfiles, math.floor(nbytes / 1024 / 1024)))
            else:
                print('target includes all source volumes')
        raise Exception('not implemented')

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
        if not os.environ.get('SSH_AUTH_SOCK', ''):
            raise Exception('SSH_AUTH_SOCK not set -- you should be running ssh-agent')
        sources = [argv[2], str(Path(argv[0]).with_name('req.txt')), argv[0]] # config, req.txt, and .py files
        for h in selected:
            ksync.install(h, sources)
    elif cmd == 'pull':
        if not os.environ.get('SSH_AUTH_SOCK', ''):
            raise Exception('SSH_AUTH_SOCK not set -- you should be running ssh-agent')
        for h in selected:
            ksync.pull(h)
    elif cmd == 'fprint':
        if len(argv) > 3:
            raise Exception('fprint runs locally only')
        if fullmode:
            ksync.write_full()
        else:
            ksync.write_incremental()
    elif cmd == 'pull':
        if not os.environ.get('SSH_AUTH_SOCK', ''):
            raise Exception('SSH_AUTH_SOCK not set -- you should be running ssh-agent')
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
