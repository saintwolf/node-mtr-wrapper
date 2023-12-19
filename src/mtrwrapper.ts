import {ChildProcess, spawn} from "child_process";
import * as net from "net";
import { EventEmitter } from "events";

const regexPatternMtr = /^\s+?(?<hopID>[0-9]+)[.\|\-\s]+(?<hopAddress>[a-zA-Z0-9.i_\-\?]+)\s+(?<loss>[a-zA-Z0-9.]+)%?\s+(?<snt>[a-zA-Z0-9.]+)\s+(?<drop>[a-zA-Z0-9.]+)\s+(?<rcv>[a-zA-Z0-9.]+)\s+(?<last>[a-zA-Z0-9.]+)\s+(?<best>[a-zA-Z0-9.]+)\s+(?<avg>[a-zA-Z0-9.]+)\s+(?<wrst>[a-zA-Z0-9.]+)\s+(?<jttr>[a-zA-Z0-9.]+)\s+(?<javg>[a-zA-Z0-9.]+)\s+(?<jmax>[a-zA-Z0-9.]+)\s+(?<jint>[a-zA-Z0-9.]+)$/i;

interface TracerouteOptions {
    packetLen?: number;
    resolveDns?: boolean;
}

enum AddressType {
    Unknown = 0,
    IPv4 = 4,
    IPv6 = 6,
}
  

class MtrWrapper {
    private _target: string;
    private _options: TracerouteOptions;
    private _addressType: AddressType;
    private _hrStart: [number, number];

    constructor(target: string, options: TracerouteOptions) {
        this._target = target
        this._options = {
            packetLen: options.packetLen || 60,
            resolveDns: options.resolveDns || false,
        }
    }

    async Traceroute(callback = (error, result) => {}) {
        return new Promise((resolve, reject) => {
            const self = this;
            const args = [];
            // let child;
            // let emitter;
            let stdoutBuffer;
            let stderrBuffer;
            let data;
        

            // Tests if input is an IP address. Returns 0 for invalid strings,
            // returns 4 for IP version 4 addresses, and returns 6
            // for IP version 6 addresses
            if (net.isIPv4(this._target)) {
                this._addressType = AddressType.IPv4;
                // Use IPv4 only
                args.push('-4');
            } else if (net.isIPv6(this._target)) {
                this._addressType = AddressType.IPv6;
                // Use IPv6 only
                args.push('-6');
            } else {
                throw new Error('Target is not a valid IPv4 or IPv6 address');
            }
        
            // Using this option to force mtr to display numeric IP numbers and not try
            //     to resolve the host names
            if (!this._options.resolveDns) {
                args.push('--no-dns');
            }
        
            // Use this option to specify the fields and their order when loading mtr
            args.push('-o LSDR NBAW JMXI');
        
            // This option puts mtr into report mode
            args.push('-r');
        
            // This option puts mtr into wide report mode. When in this mode, mtr will not cut hostnames in the report.
            args.push('-w');
        
            // These options or a trailing PACKETSIZE on the commandline sets the packet size used for probing. It is in bytes inclusive IP and ICMP headers
            if (this._options.packetLen) {
                args.push('--psize');
                args.push(this._options.packetLen);
            }
        
            args.push(this._target);
            this._hrStart = process.hrtime();
            const child = spawn('mtr', args);
        
            stdoutBuffer = '';
            stderrBuffer = '';
        
            child.stdout.on('data', function(chunk) {
                stdoutBuffer += chunk;
            });
        
            child.stderr.on('data', function(chunk) {
                stderrBuffer += chunk;
            });
        
            child.on('exit', function(code) {
                let err;
                data = {
                    args: args,
                    code: code,
                    status: 'success',
                    timetaken: process.hrtime(this._hrStart)
                };
                if (code === 0) {
                    data.results = self._parseResult(stdoutBuffer);
                    resolve(data);
                    callback(null, data);
                } else {
                    data.status = 'failed';
                    data.results = {
                        raw: stderrBuffer
                    };
                    err = new Error();
                    err.data = data;
                    reject(err);
                    callback(err, null);
                }
            });
            child.on('error', function(error) {
                reject(error);
                callback(error, null);
            });
        });
    }

    private _spawn(cmd: string, args: string[]) {
        const child = spawn(cmd, args);
        return child;
    }

    private _parseResult(output) {
        const lines = output.split('\n');
        const parsedResults = {
            raw: output,
            hops: []
        };
        let captureGroups;

        lines.forEach((line) => {
            captureGroups = regexPatternMtr.exec(line);
            if (captureGroups) {
                parsedResults.hops.push(captureGroups.groups);
            }
        });
        return parsedResults;
    }

}

export default MtrWrapper;