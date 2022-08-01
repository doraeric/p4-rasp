#!/usr/bin/env node
import { spawn } from "child_process";
import { promises as fs } from "fs";
import { program } from "commander";

program
  .option(
    "-o, --output <filename>",
    "path to output (csv/tsv format)",
    "num_sockets.tsv"
  )
  .option("-t, --timeout <sec>", "Stop monitoring when timeout", "0");

program.parse();

const options = program.opts();
/** @type {string} */
const num_sockets_file = options.output;
const sep = num_sockets_file.endsWith(".csv") ? "," : "\t";
const monitorTimeout = parseFloat(options.timeout);

async function main() {
  const pgrep_p = spawn("pgrep", ["-f", "apache2 -k"]);
  let buf = "";
  pgrep_p.stdout.on("data", (data) => {
    buf += data;
  });
  await new Promise((resolve, reject) => {
    pgrep_p.on("close", (code) => {
      if (code == 0) {
        resolve();
      } else {
        reject(code);
      }
    });
  });
  const pids = buf.trim().split(/\r?\n/);
  console.log(`strace pids: ${pids}`);

  buf = "";
  const pgrep_p_h1 = spawn("pgrep", ["-f", "mininet:h1"]);
  pgrep_p_h1.stdout.on("data", (data) => (buf += data));
  await new Promise((resolve, reject) => {
    pgrep_p_h1.on("close", (code) => {
      if (code == 0) {
        resolve();
      } else {
        console.log(code);
        reject(code);
      }
    });
  });
  const h1Pid = buf.trim().split(/\r?\n/)[0];
  console.log(`h1 pid: ${h1Pid}`);
  /**
   * @type {{
   *   [key: string]: 'new' | 'accepted' | 'closed'
   * }}
   */
  const sockets = {};
  const numSockets = { new: 0, accepted: 0, closed: 0 };
  await fs.writeFile(
    num_sockets_file,
    `timestamp${sep}new${sep}accepted${sep}closed\n`
  );
  const socketUpdate = async (timestamp) => {
    const { new: newSocket, accepted, closed } = numSockets;
    const p = fs.appendFile(
      num_sockets_file,
      `${timestamp}${sep}${newSocket}${sep}${accepted}${sep}${closed}\n`
    );
    await p;
  };

  const strace_ps = pids.map((line) => {
    return spawn("sudo", [
      "strace",
      "-ttt",
      "-T",
      "-ff",
      "-e",
      "trace=accept,accept4",
      "-e",
      "status=!failed",
      "-p",
      line,
      // "-o",
      // `apache`,
    ]);
  });
  strace_ps.forEach((p) => {
    let buf = "";
    p.stderr.on("data", (/** @type {Buffer} */ data) => {
      buf += data.toString();
      buf = buf.split(/\r?\n/);
      buf.slice(0, -1).forEach((line) => {
        p.emit("line", line);
      });
      buf = buf.slice(-1)[0];
    });
    p.on("line", (/** @type {string} */ line) => {
      // https://stackoverflow.com/questions/546433/regular-expression-to-match-balanced-parentheses
      const result = line.match(
        /(\[pid (?<pid>\d+)\] )?(?<timestamp>\d+\.\d+) (?<syscall>\w+)(?<argstr>\((?:[^)(]+|\((?:[^)(]+|\([^)(]*\))*\))*\)) = (?<ret>\d+) <(?<deltatime>\d+\.\d+)/
      );
      if (result === null) {
        console.log(line);
      } else {
        const syscall = result.groups.syscall;
        if (syscall === "accept4") {
          const args = result.groups.argstr.match(
            /sin_port=htons\((?<port>\d+)\), sin_addr=inet_addr\(["'](?<addr>[\d\.]+)["']\)/
          );
          if (args === null) {
            console.log(args);
          } else {
            const addr = args.groups.addr;
            const port = parseInt(args.groups.port);
            const returnTimestamp =
              parseFloat(result.groups.timestamp) +
              parseFloat(result.groups.deltatime);
            p.emit("accept4", { addr, port, returnTimestamp });
          }
        } else {
          console.log(`unhandle event: ${syscall}`);
        }
      }
    });
    p.on(
      "accept4",
      /**
       * @param {{
       *   addr: string,
       *   port: number,
       *   returnTimestamp: number,
       * }} args
       */
      ({ addr, port, returnTimestamp: timestamp }) => {
        const key = `${addr}:${port}`;
        if (sockets[key] === "new") {
          numSockets["new"] -= 1;
        }
        numSockets["accepted"] += 1;
        sockets[key] = "accepted";
        socketUpdate(timestamp);
      }
    );
    p.on("close", (code) => {
      console.log(`strace exit code ${code}`);
    });
  });

  const conntrack_p = spawn("sudo", [
    "nsenter",
    "-a",
    "-t",
    h1Pid,
    "/usr/sbin/conntrack",
    "-E",
    "-o",
    "timestamp",
    "--protonum",
    "tcp",
    "--dst",
    "10.0.1.1",
    "-b",
    "1048576",
  ]);
  (() => {
    let buf = "";
    conntrack_p.stdout.on("data", (/** @type {Buffer} */ data) => {
      buf += data.toString();
      buf = buf.split(/\r?\n/);
      buf.slice(0, -1).forEach((line) => {
        conntrack_p.emit("line", line);
      });
      buf = buf.slice(-1)[0];
    });
    conntrack_p.on("line", (/** @type {string} */ line) => {
      const result = line.match(
        /\[(?<timestamp>\d+\.\d+)\]\s+\[(?<event>\w+)\]\s+(?<proto>\w+)\s+\d+\s+(\d+\s+(?<state>\w+)\s+)?src=(?<src>[^\s]+)\s+dst=(?<dst>[^\s]+)\s+sport=(?<sport>\d+)\s+dport=(?<dport>\d+)/
      );
      if (result === null) {
        console.log(line);
      } else {
        const timestamp = parseFloat(result.groups.timestamp),
          event = result.groups.event,
          proto = result.groups.proto,
          state = result.groups?.state || null,
          src = result.groups.src,
          dst = result.groups.dst,
          sport = parseInt(result.groups.sport),
          dport = parseInt(result.groups.dport);
        const key = `${src}:${sport}`;
        if (event === "NEW") {
          sockets[key] = "new";
          numSockets["new"] += 1;
          socketUpdate(timestamp);
        } else if (event === "UPDATE") {
          if (
            ["SYN_SENT", "SYN_RECV", "ESTABLISHED"].includes(state) &&
            !sockets.hasOwnProperty(key)
          ) {
            sockets[key] = "new";
            numSockets["new"] += 1;
            socketUpdate(timestamp);
          } else if (
            [
              "FIN_WAIT",
              "CLOSE_WAIT",
              "LAST_ACK",
              "TIME_WAIT",
              "CLOSE",
            ].includes(state)
          ) {
            if (sockets[key] === "new") {
              sockets[key] = "closed";
              numSockets["new"] -= 1;
              numSockets["closed"] += 1;
              socketUpdate(timestamp);
            } else if (sockets[key] === "accepted") {
              sockets[key] = "closed";
              numSockets["accepted"] -= 1;
              numSockets["closed"] += 1;
              socketUpdate(timestamp);
            }
          }
        } else if (event === "DESTROY") {
          if (sockets[key] === "new") {
            sockets[key] = "closed";
            numSockets["new"] -= 1;
            numSockets["closed"] += 1;
            socketUpdate(timestamp);
          } else if (sockets[key] === "accepted") {
            sockets[key] = "closed";
            numSockets["accepted"] -= 1;
            numSockets["closed"] += 1;
            socketUpdate(timestamp);
          }
        }
      }
    });
  })();

  const exitAll = () => {
    strace_ps.forEach((p) => p.kill());
    conntrack_p.kill();
    process.exit();
  };
  let timeoutObj = null;
  if (monitorTimeout > 0) {
    timeoutObj = setTimeout(() => {
      console.log("Monitor timeout");
      exitAll();
    }, monitorTimeout * 1000);
  }

  process.on("SIGINT", () => {
    console.log("Caught interrupt signal");
    if (timeoutObj !== null) clearTimeout(timeoutObj);
    exitAll();
  });
}
main();
