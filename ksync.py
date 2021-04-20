#!./pyenv/bin/python

import heapq, os, socket, shlex, time
import getpass, hashlib, json, subprocess, toml

from datetime import datetime
from pathlib import Path

printonly = False

### TODO: track of deleted files to see whether a given fingerprint really still
### exists after an incremental deletion.
###
### TODO: handle specific interfaces (LANs) being bound to specific egress

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

def scp_toremote(user, host, localsource, remotedest, port=None):
    print('copying %s to %s@%s:%s' % (localsource, user, host, remotedest))
    localsources = localsource if type(localsource) == type([]) else [localsource]
    parg = ['-P%d' % port] if port else []
    if not printonly:
        subprocess.run(['scp'] + parg + localsources + ['%s@%s:%s' % (user, host, remotedest)], check=True)

def scp_fromremote(user, host, remotesource, localdest, port=None, args=[]):
    print('copying %s@%s:%s to %s' % (user, host, remotesource, localdest))
    remotesources = remotesource if type(remotesource) == type([]) else [remotesource]
    earg = ['ssh -p%d' % port] if port else ['ssh']
    if not printonly:
        subprocess.run(['rsync', '--checksum', '--partial-dir=.rsync-partial', '-e'] + earg + args + ['%s@%s:%s' % (user, host, r) for r in remotesources] + [localdest], check=True)

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

def round_gb(nbytes):
    return round(nbytes / 1024.0 / 1024.0 / 1024.0, 1)

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
    
    def __init__(self, hostdict, directory='.', pattern='%s-20*.fprint'):
        hostlist = hostdict.get('dns', [])
        for host in hostlist:
            hostpattern = pattern % host
            matches = [x for x in Path(directory).glob(hostpattern)]
            if matches:
                break
        else:
            raise FileNotFoundError('no files matching %s for hosts %s in directory %s' % (pattern, ' '.join(hostlist), directory))
        self.stack = []
        self.top_filename = matches[-1]
        self._load(self.top_filename)

    def _load(self, fname):
        with open(fname, 'rt') as f:
            j = json.load(f)
            self.stack.append(j)
            based_on = j.get('based_on', '')
            if based_on:
                self._load(based_on)

    def get_top_filename(self):
        return self.top_filename

    def get_volumes(self):
        return self.stack[0]['volumes'] # most recent incremental

    def items(self):
        """returns an iterator over all the (fingerprint, filelist) items"""
        fprints = [x['fprints'].items() for x in self.stack]
        lastfp = None
        for pair in heapq.merge(*fprints, key=lambda p: p[0]):
            not_eadir = False
            for f in pair[1]:
                if f[0].find('/@eaDir') == -1:
                    not_eadir = True
                    break
            if lastfp != pair[0] and not_eadir:
                lastfp = pair[0]
                yield pair
                

class CopySelector:
    def __init__(self, srciter, targiter, prefixmap_src2targ):
        (self.srciter, self.targiter, self.prefixmap) = (srciter, targiter, prefixmap_src2targ)

    def _advance_targ(self):
        if self.targpair is not None:
            try:
                self.targpair = next(self.targiter)
            except StopIteration:
                self.targpair = None

    def __iter__(self):
        """returns an iterator over (fprint, srcfilelist, targprefix) for every fprint in src but not targ"""
        self.targpair = True
        self._advance_targ()
        for srcpair in self.srciter:
            fprint = srcpair[0]
            while self.targpair and self.targpair[0] < fprint:
                self._advance_targ()
            # now targ has fingerprint >= fprint
            if self.targpair and self.targpair[0] == fprint:
                # targ already has fprint, no need to copy
                continue
            def match(filelist, prefix):
                for f in filelist:
                    if f[0].startswith(prefix):
                        return True
                return False
            for (srcprefix, targprefix) in self.prefixmap:
                if match(srcpair[1], srcprefix):
                    yield (fprint, srcpair[1], targprefix)
                    break

class PathPrefixCounter:
    def __init__(self):
        self.counts = {}
    def add_path(self, path, nbytes):
        for parent in Path(path).parents:
            lst = self.counts.get(parent, None)
            if lst:
                lst[0] += 1
                lst[1] += nbytes
            else:
                self.counts[parent] = [1, nbytes]
    def get_counts(self):
        return sorted(self.counts.items())

class BandwidthManager:
    def __init__(self, config):
        self.bwlimits = config.get('bandwidth', {})
        self.inuse = {}

    def start(self, bw):
        if bw:
            self._modify_inuse(bw)
    def stop(self, bw):
        if bw:
            (srchostname, targhostname, delta) = bw
            self._modify_inuse((srchostname, targhostname, -delta))

    def __str__(self):
        s = ''
        for (name, d) in self.inuse.values():
            bwin = d.get('ingress', 0)
            bwout = d.get('egress', 0)
            stin = (' %d in' % bwin) if bwin else ''
            stout = (' %d out' % bwout) if bwout else ''
            if bwin or bwout:
                s += '%s%s:%s%s' % (', ' if s else '', name, stin, stout)
        return s if s else '[no bandwidth in use]'


    def _modify_inuse(self, bw):
        """positive delta is Mbps of flow being started; negative is Mbps of flow being stopped"""
        (srchostname, targhostname, delta) = bw
        srcdict = self.inuse.get(srchostname, {})
        if not srcdict:
            srcdict['egress'] = 0
            srcdict['ingress'] = 0
            self.inuse[srchostname] = srcdict
        targdict = self.inuse.get(targhostname, {})
        if not targdict:
            targdict['egress'] = 0
            targdict['ingress'] = 0
            self.inuse[targhostname] = targdict
        srcdict['egress'] += delta
        targdict['ingress'] += delta
        assert srcdict['egress'] >= 0 and targdict['ingress'] >= 0, (srcdict, targdict)

    def select(self, srchost, targhost):
        for srcp in srchost.get('public', []):
            if srcp in targhost.get('public', []):
                return None # on_lan

        srcpublicnames = srchost.get('public', [])
        targpublicnames = targhost.get('public', [])

        egresslimits = [self._getlimit(self.bwlimits.get(p, {}), 'egress') for p in srcpublicnames]
        ingresslimits = [self._getlimit(self.bwlimits.get(p, {}), 'ingress') for p in targpublicnames]

        srcheadroom = [lim - self.inuse.get(name, {}).get('egress', 0) for (name, lim) in zip(srcpublicnames, egresslimits)]
        targheadroom = [lim - self.inuse.get(name, {}).get('ingress', 0) for (name, lim) in zip(targpublicnames, ingresslimits)]

        bw = min(max(srcheadroom), max(targheadroom))
        srcname = None
        for (name, hr) in zip(srcpublicnames, srcheadroom):
            if hr >= bw:
                srcname = name
                break
        assert srcname
        for (name, hr) in zip(targpublicnames, targheadroom):
            if hr >= bw:
                targname = name
                break
        assert targname
        return (srcname, targname, bw)

    def _getlimit(self, lim, name):
        override = lim.get('override', {})
        ovstart = override.get('start', 0)
        ovend = override.get('end', 0)
        hour = datetime.now().hour
        if (ovstart < ovend and ovstart <= hour and hour < ovend) or \
           (ovend < ovstart and (hour < ovend or hour >= ovstart)):
            return override.get(name, 10000)
        else:
            return lim.get(name, 10000)


class Ksync:
    def __init__(self, config, quietmode, hostname):
        (self.config, self.quietmode) = (config, quietmode)
        self.lastlogline = ''
        self.hostname = config.get('hostmap', {}).get(hostname, hostname)

        if 'hosts' not in config:
            raise Exception('config must have hosts section')
        self.me = self._gethost(self.hostname, ifnone={})
        self.bwm = BandwidthManager(self.config)
        self.copy_processes = []

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
        ssh(self._getvar('ssh_user', host=host), host['dns'][0], cmd, tty=tty, check=check)
    def _scp_toremote(self, host, localsources, remotedest):
        scp_toremote(self._getvar('ssh_user', host=host), host['dns'][0], localsources, remotedest)
    def _scp_fromremote(self, host, remotesources, localdest):
        scp_fromremote(self._getvar('ssh_user', host=host), host['dns'][0], remotesources, localdest)

    def _log(self, line):
        if line == self.lastlogline:
            print('.',)
        else:
            self.lastlogline = line
            print(line)

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

    def _recurse(self, path, symlinks, fprints, base_files={}):
        if path.is_symlink():
            s = path.lstat()
            symlinks.append((str(path), os.readlink(path), s.st_mode, s.st_ctime, s.st_mtime))
        elif path.is_file():
            s = path.stat()
            payload = (str(path), s.st_size, s.st_nlink, s.st_mode, s.st_ctime, s.st_mtime)
            base_payload = base_files.get(payload[0], None)
            if base_payload is not None:
                if base_payload[1] == payload[1] and base_payload[5] == payload[5]:
                    return # we are incremental and parent has file with same size and mtime
            h = FileHasher(path)
            fp = h.do_hash()
            existing = fprints.get(fp, None)
            if existing is not None:
                existing.append(payload)
            else:
                fprints[fp] = [payload]
        elif path.is_dir():
            if path.parts[-1] != '@eaDir':
                if not self.quietmode:
                    print(path)
                try:
                    for p in path.iterdir():
                        try:
                            self._recurse(p, symlinks, fprints, base_files)
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
            self._recurse(Path(volume), symlinks, fprints)
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
        volumes = self.me.get('volumes', [])
        if not volumes:
            raise Exception('config file entry for %s in hosts section must have volumes' % self.hostname)

        workdir = self._getvar('working_directory', default='.')
        if base is None:
            # use the most recent fprint
            snap = Snapshot(self.me, directory=workdir)
        else:
            snap = Snapshot(self.me, directory=workdir, pattern=base)
        base_files = {}
        for (fp, flist) in snap.items():
            for f in flist:
                base_files[f[0]] = [fp] + f[1:]

        started = datetime.now().replace(microsecond=0)
        symlinks = []
        fprints = {}
        for volume in volumes:
            self._recurse(Path(volume), symlinks, fprints, base_files)
        fprintpath = Path(workdir, '%s-%s.fprint' % (self.hostname, started.isoformat()))
        with fprintpath.open('wt') as fprint:
            fprint.write("""
{
  "based_on": "%s",
  "started": "%s",
  "function": "SHA-256",
  "volumes": %s,
  "symlinks":
""" % (snap.get_top_filename(), started.isoformat(), json.dumps(volumes)))
            json.dump(sorted(symlinks), fprint)
            fprint.write(""",
  "fprints":
""")
            json.dump(fprints, fprint, sort_keys=True)
            fprint.write("""
}
""")
            
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
        workdir = self._getvar('working_directory', default='.')
        srchost = self._gethost(source)
        targhost = self._gethost(target)
        src = Snapshot(srchost, directory=workdir)
        targ = Snapshot(targhost, directory=workdir)
        targvolumes = {}
        srcmatchprefixes = {}
        targmatchprefixes = {}
        for v in targ.get_volumes():
            p = Path(v).name
            if p in targvolumes:
                raise Exception('target %s has two paths for volume %s: %s' % (target, p, repr(targ.get_volumes())))
            targvolumes[p] = v
        (ignoredvolumes, ignoredfiles, ignoredbytes, matchfiles, matchbytes) = ([], 0, 0, 0, 0)
        for v in src.get_volumes():
            targprefix = targvolumes.get(Path(v).name, None)
            if targprefix:
                if v in srcmatchprefixes:
                    raise Exception('source %s has two paths for volume %s: %s' % (source, v, repr(src.get_volumes())))
                srcmatchprefixes[v] = targprefix
                assert not targprefix in targmatchprefixes, (targprefix, targmatchprefixes)
                targmatchprefixes[targprefix] = v
            else:
                ignoredvolumes.append(v)
        def matches(prefix, payloads):
            for p in payloads:
                if p[0].startswith(prefix):
                    return True
            return False
        for (fprint, payloadlist) in src.items():
            for prefix in srcmatchprefixes:
                if matches(prefix, payloadlist):
                    matchfiles += 1
                    matchbytes += payloadlist[0][1]
                    break
            else:
                ignoredfiles += 1
                ignoredbytes += payloadlist[0][1]
        if not self.quietmode:
            if ignoredfiles or ignoredvolumes or ignoredbytes:
                print('ignoring source %s volumes %s (%d files in %s GB) not in target %s' % (source, ', '.join(ignoredvolumes), ignoredfiles, round_gb(ignoredbytes), target))
            else:
                print('target %s includes all volumes from source %s' % (target, source))

        (nbytes, copies, pathprefix_counts) = (0, [], PathPrefixCounter())
        selector = CopySelector(src.items(), targ.items(), srcmatchprefixes.items())
        for (fprint, srcfilelist, targprefix) in selector:
            srcprefix = targmatchprefixes[targprefix]
            for f in srcfilelist:
                if f[0].startswith(srcprefix):
                    copies.append((f[0], f[0].replace(srcprefix, targprefix, 1), targprefix))
                    start = srcprefix.rfind('/')
                    pathprefix_counts.add_path(f[0].replace(srcprefix, srcprefix[start:], 1), f[1])
                    break
            else:
                assert False, 'no matching prefix for %s' % ' '.join(srcfilelist)
            nbytes += srcfilelist[0][1]

        targfiles = {}
        for (fprint, payloadlist) in targ.items():
            for p in payloadlist:
                targfiles[p[1]] = True
        replacefiles = 0
        for (src, targ, targprefix) in copies:
            if targ in targfiles:
                replacefiles += 1
        print('copying %d files in %s GB replacing %d files [total %d files in %s GB on matching volumes]' % (len(copies), round_gb(nbytes), replacefiles, matchfiles, round_gb(matchbytes)))

        (lastprefix, lastlst) = ('/', [0, 0])
        for (prefix, lst) in pathprefix_counts.get_counts():
            strprefix = str(prefix)
            if strprefix.startswith(lastprefix) and lst == lastlst:
                continue
            if lst[0] > 9 and nbytes < lst[1] * 100:
                assert lastprefix[0] == '/', lastprefix
                assert strprefix[0] == '/', strprefix
                slash = 0
                for n in range(1, min(len(lastprefix), len(strprefix))):
                    if strprefix[n] == '/':
                        slash = n
                    if lastprefix[n] != strprefix[n]:
                        break
                spaced = strprefix[slash:].rjust(len(strprefix), ' ')
                print('%s: %s GB in %d files' % (spaced, round_gb(lst[1]), lst[0]))
                (lastprefix, lastlst) = (strprefix, lst)

        last = datetime.now()
        sorted_copies = sorted(copies)
        while sorted_copies or self.copy_processes:
            sorted_copies = self._schedule_copy(sorted_copies, srchost, targhost)
            if (datetime.now() - last).seconds > 1*60:
                self._log('%d files not started; %d copies %s' % (len(sorted_copies), len(self.copy_processes), self.bwm))
                last = datetime.now()

        self._log('completed successfully')

    def _schedule_copy(self, sorted_copies, srchost, targhost):
        """sorted_copies is a list of (sourcefilename, targetfilename, targetprefix) tuples of all files
           remaining to be copied, sorted lexicographically by sourcefilename.

           If bandwidth is available to start a new copy, we start a copy of the first N files in
           sorted_copies. If bandwidth is not available, we wait one minute for bandwidth to
           become available (and/or a previously started copy to end). Either way we return a suffix
           of sorted_copies representing the files for which no copy has been started.
        """
        running_processes = []
        if self.copy_processes:
            for (bw, p) in self.copy_processes:
                retval = p.poll()
                if retval is None:
                    running_processes.append((bw, p)) # not terminated
                else:
                    if retval:
                        self._log('%s aborted with code %d' % (p.args, retval))
                        # TODO: restart this once?
                    self.bwm.stop(bw)
            if running_processes:
                time.sleep(1)
        self.copy_processes = running_processes
        if not sorted_copies:
            return sorted_copies
        
        # host is the host we are sshing to, and otherhost is the host running ssh
        def userhost(host, otherhost, sel):
            user = self._getvar('ssh_user', host)
            otheruser = self._getvar('ssh_user', otherhost)
            userprefix = '' if user == otheruser else '%s@' % user
            if sel is None:
                return (None, '%s%s:' % (userprefix, host['dns'][0])) # None = no override of ssh port
            (srcname, targname, bw) = sel
            if bw == 0:
                return (None, None)
            bwmap = self.config.get('bandwidth', {})
            ports = self._getvar('scp_ports', host, default=[])
            srcegressports = bwmap.get(srcname, {}).get('egress_ports', []) or ports
            targegressports = bwmap.get(targname, {}).get('egress_ports', []) or ports
            srcingressok = not gwmap.get(srcname, {}).get('no_ingress_ports', None)
            targingressok = not gwmap.get(targname, {}).get('no_ingress_ports', None)
            if srcname in host.get('public', []):
                # case (B): on targhost, ssh -p targegressport srcname:<path> <localfilename>
                for port in targegressports:
                    if port in ports and srcingressok:
                        return (port, '%s%s:' % (userprefix, srcname))
                return (None, None)
            else:
                # case (A): on srchost, ssh -p srcegressport <localfilename> targname:<path>
                assert srcname in otherhost.get('public', []), (host, otherhost, srcname, targname)
                for port in srcegressports:
                    if port in ports and targingressok:
                        return (port, '%s%s:' % (userprefix, targname))
                return (None, None)

        sel = self.bwm.select(srchost, targhost)

        # sel is None or (srcname, targname, bw). If sel is None, the copy is on the LAN, is not
        # bandwidth-restricted, and should be made to one of the 'dns' names on port 22.
        # If bw is 0, a copy cannot proceed. Otherwise, rsync may be run
        #  (A) locally on the source host, to targhost at any of the ports for srchost in bandwidth AND
        #      in targhost; OR
        #  (B) locally on the target host, from srchost at any of the ports for targhost in bandwidth AND
        #      in srchost.
        # If there is no port that is both in bandwidth and in targhost, rsync may not be
        # run on the source host (i.e. case (A) is forbidden). If there is no port that is both in
        # bandwidth and in srchost, rsync may not be run on the target host (case (B) is forbidden).
        # If both cases are forbidden, a copy may not proceed between that host-pair.
        
        (srcport, srcuserhost) = userhost(srchost, targhost, sel) # case B
        (targport, targuserhost) = userhost(targhost, srchost, sel) # case A

        if (not srcuserhost) and (not targuserhost):
            return sorted_copies # we can't start a copy right now

        assert sorted_copies # we checked for this above

        CHUNKSIZE = 10 # FIXME, use file size
        prefix = sorted_copies[0][2]
        chunk = [f for f in sorted_copies[:CHUNKSIZE] if f[2] == prefix]

        # chunk are the next CHUNKSIZE files with the same prefix (e.g. in the same volume).
        # we are local to either src or targ and need to adjust the relative path root accordingly

        def addrelative(toinsert, complete, prefix):
            # we insert /./ at the point in "toinsert" where the volume ends; that is where
            # rsync should treat the relative path as beginning.
            assert complete.startswith(prefix), (toinsert, complete, prefix)
            suffix = complete[len(prefix):]
            assert toinsert.endswith(suffix), (toinsert, complete, prefix, suffix)
            pivot = len(toinsert) - len(suffix)
            return '%s/.%s' % (toinsert[:pivot], toinsert[pivot:])

        if srcuserhost: # then we will run rsync on targhost
            if self.me.get('dns', ['']) == targhost['dns']:
                sshwrap = []
            else:
                sshwrap = ['ssh', '-nxAT', '%s@%s' % (self._getvar('ssh_user', targhost), targhost['dns'][0])]
            earg = ['ssh -p%s' % srcport] if srcport else ['ssh']
            sources = ['%s%s' % (srcuserhost, addrelative(f[0], f[1], f[2])) for f in chunk]
            dest = [chunk[0][2]]
        else: # we will run rsync on srchost
            assert targuserhost
            if self.me.get('dns', ['']) == srchost['dns']:
                sshwrap = []
            else:
                sshwrap = ['ssh', '-nxAT', '%s@%s' % (self._getvar('ssh_user', srchost), srchost['dns'][0])]
            earg = ['ssh -p%s' % targport] if targport else ['ssh']
            sources = [addrelative(f[0], f[1], f[2]) for f in chunk]
            dest = ['%s%s' % (targuserhost, chunk[0][2])]

        if printonly:
            sshwrap = ['echo'] + sshwrap
        bwlimit = ['--bwlimit=%d' % (sel[2]*1000)] if (sel and sel[2]) else []
        p = subprocess.Popen(sshwrap + ['rsync'] + bwlimit + ['--protect-args', '--checksum', '--relative', '--partial-dir=.rsync-partial', '-e'] + ([shlex.quote(f) for f in earg + sources + dest] if sshwrap else (earg + sources + dest)))
        self.bwm.start(sel)
        self.copy_processes.append((sel, p))
        return sorted_copies[len(chunk):]

    
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
    elif cmd == 'cp':
        if len(argv) != 5:
            raise Exception('Usage: %s %s configfile sourcehost targethost' % (argv[0], argv[1]))
        ksync.sync(argv[3], argv[4])
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
