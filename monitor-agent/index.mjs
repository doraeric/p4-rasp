#!/usr/bin/env node
import { spawn } from "child_process";
import { promises as fs } from "fs";
import { program } from "commander";
import path from "node:path";

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
const stepChartPath = (() => {
  const parsed = path.parse(num_sockets_file);
  return path.format({
    root: parsed.root,
    dir: parsed.dir,
    base: `${parsed.name}-step-chart${parsed.ext}`,
  });
})(num_sockets_file);

async function main() {
  const h1Pid = await getMininetPid("h1");
  console.log(`h1 pid: ${h1Pid}`);
  /**
   * @type {{
   *   [key: string]: 'new' | 'accepted' | 'closed'
   * }}
   */
  const sockets = {};
  const numSockets = { new: 0, accepted: 0, closed: 0 };
  let lastTimestamp = 0;
  const startTime = Date.now() / 1000;
  await fs.writeFile(
    num_sockets_file,
    `timestamp${sep}new${sep}accepted${sep}closed\n` +
      `${startTime}${sep}0${sep}0${sep}0\n`
  );
  await fs.writeFile(
    stepChartPath,
    `timestamp${sep}new${sep}accepted${sep}closed\n` +
      `${startTime}${sep}0${sep}0${sep}0\n`
  );
  /**
   * @param {string} filepath
   * @param {number} timestamp
   * @param {{
   *   new: number,
   *   accepted: number,
   *   closed: number
   * }} numSockets
   */
  const writeNumFile = async (
    filepath,
    timestamp,
    { new: _new, accepted, closed }
  ) => {
    const p = fs.appendFile(
      filepath,
      `${timestamp}${sep}${_new}${sep}${accepted}${sep}${closed}\n`
    );
    await p;
  };

  /**
   * @param {{
   *   timestamp: number,
   *   addr: string,
   *   port: number,
   * }}
   */
  const newSocket = ({ timestamp, addr, port }) => {
    const key = `${addr}:${port}`;
    if (!sockets.hasOwnProperty(key)) {
      if (lastTimestamp < timestamp) lastTimestamp = timestamp;
      writeNumFile(stepChartPath, timestamp, { ...numSockets });
      sockets[key] = "new";
      numSockets["new"] += 1;
      writeNumFile(num_sockets_file, timestamp, { ...numSockets });
      writeNumFile(stepChartPath, timestamp, { ...numSockets });
    }
  };

  /**
   * @param {{
   *   timestamp: number,
   *   addr: string,
   *   port: number,
   * }}
   */
  const acceptSocket = ({ timestamp, addr, port }) => {
    if (lastTimestamp < timestamp) lastTimestamp = timestamp;
    // timestamp from audit is about 1~2 ms earlier than strace
    // so it's okay to add some time to sync with conntrack
    if (timestamp < lastTimestamp) timestamp = lastTimestamp;
    writeNumFile(stepChartPath, timestamp, { ...numSockets });
    const key = `${addr}:${port}`;
    if (sockets[key] === "new") {
      numSockets["new"] -= 1;
    }
    numSockets["accepted"] += 1;
    sockets[key] = "accepted";
    writeNumFile(num_sockets_file, timestamp, { ...numSockets });
    writeNumFile(stepChartPath, timestamp, { ...numSockets });
  };

  /**
   * @param {{
   *   timestamp: number,
   *   addr: string,
   *   port: number,
   * }}
   */
  const closeSocket = ({ timestamp, addr, port }) => {
    const key = `${addr}:${port}`;
    if (sockets[key] !== "closed") {
      if (lastTimestamp < timestamp) lastTimestamp = timestamp;
      writeNumFile(stepChartPath, timestamp, { ...numSockets });
      if (sockets[key] === "new") {
        numSockets["new"] -= 1;
      } else if (sockets[key] === "accepted") {
        numSockets["accepted"] -= 1;
      }
      sockets[key] = "closed";
      numSockets["closed"] += 1;
      writeNumFile(num_sockets_file, timestamp, { ...numSockets });
      writeNumFile(stepChartPath, timestamp, { ...numSockets });
    }
  };

  await addAudit();
  const tail_audit_p = spawn("sudo", [
    "tail",
    "-n0",
    "-f",
    "/var/log/audit/audit.log",
  ]);
  ((p) => {
    let buf = "";
    p.stdout.on("data", (/** @type {Buffer} */ data) => {
      buf += data.toString();
      buf = buf.split(/\r?\n/);
      buf.slice(0, -1).forEach((line) => {
        p.emit("line", line);
      });
      buf = buf.slice(-1)[0];
    });
    const eventBuf = new Set();
    p.on("line", (/** @type {string} */ line) => {
      if (line.startsWith("type=SYSCALL") || line.startsWith("type=SOCKADDR")) {
        const result = line.match(
          /type=(?<type>\w+) msg=audit\((?<timestamp>[\d+\.]+):(?<event_id>\d+)\): (?<msg>.*)$/
        );
        if (result === null) {
          console.log(line);
        } else {
          const { type, msg } = result.groups;
          const timestamp = parseFloat(result.groups.timestamp);
          const event_id = parseInt(result.groups.event_id);
          p.emit(type, { timestamp, event_id, msg });
        }
      }
    });
    p.on(
      "SYSCALL",
      /**
       * @param {{
       *   timestamp: number,
       *   event_id: number,
       *   msg: string,
       * }}
       */
      ({ timestamp, event_id, msg }) => {
        if (msg.includes(' key="socket_events"')) {
          eventBuf.add(event_id);
        }
      }
    );
    p.on(
      "SOCKADDR",
      /**
       * @param {{
       *   timestamp: number,
       *   event_id: number,
       *   msg: string,
       * }}
       */
      ({ timestamp, event_id, msg }) => {
        if (eventBuf.has(event_id)) {
          eventBuf.delete(event_id);
          const result = msg.match(
            / laddr=(?<laddr>[\d\.]+)\s+lport=(?<lport>\d+)/
          );
          if (result === null) {
            console.log(
              `type=SOCKADDR msg=audit(${timestamp}:${event_id}): ${msg}`
            );
          } else {
            const { laddr } = result.groups;
            const lport = parseInt(result.groups.lport);
            acceptSocket({ timestamp, addr: laddr, port: lport });
          }
        }
      }
    );
  })(tail_audit_p);

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
        const { event, proto, src, dst } = result.groups;
        const timestamp = parseFloat(result.groups.timestamp);
        const state = result.groups?.state || null;
        const sport = parseInt(result.groups.sport);
        const dport = parseInt(result.groups.dport);
        const key = `${src}:${sport}`;
        if (event === "NEW") {
          newSocket({ timestamp, addr: src, port: sport });
        } else if (event === "UPDATE") {
          if (["SYN_SENT", "SYN_RECV", "ESTABLISHED"].includes(state)) {
            newSocket({ timestamp, addr: src, port: sport });
          } else if (
            [
              "FIN_WAIT",
              "CLOSE_WAIT",
              "LAST_ACK",
              "TIME_WAIT",
              "CLOSE",
            ].includes(state)
          ) {
            closeSocket({ timestamp, addr: src, port: sport });
          }
        } else if (event === "DESTROY") {
          closeSocket({ timestamp, addr: src, port: sport });
        }
      }
    });
  })();

  const exitAll = async () => {
    await clearAudit();
    conntrack_p.kill();
    process.exit();
  };
  let timeoutObj = null;
  if (monitorTimeout > 0) {
    timeoutObj = setTimeout(async () => {
      console.log("Monitor timeout");
      await exitAll();
    }, monitorTimeout * 1000);
  }

  process.on("SIGINT", async () => {
    console.log("Caught interrupt signal");
    if (timeoutObj !== null) clearTimeout(timeoutObj);
    await exitAll();
  });
}
main();

function addAudit() {
  return new Promise((resolve, reject) => {
    const p = spawn("sudo", [
      "auditctl",
      "-a",
      "always,exit",
      "-F",
      "arch=b64",
      "-S",
      "accept",
      "-S",
      "accept4",
      "-F",
      "uid=http",
      "-F",
      "success=1",
      "-k",
      "socket_events",
    ]);
    p.on("close", (code) => {
      if (code === 0) {
        return resolve();
      } else {
        return reject(code);
      }
    });
  });
}

function clearAudit() {
  return new Promise((resolve, reject) => {
    const p = spawn("sudo", ["auditctl", "-D"]);
    p.on("close", (code) => {
      if (code === 0) {
        return resolve();
      } else {
        return reject(code);
      }
    });
  });
}

/**
 * @param {string} host
 * @return {Promise<string>}
 */
function getMininetPid(host) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const pgrep_p = spawn("pgrep", ["-f", `is mininet:${host}\\b`]);
    pgrep_p.stdout.on("data", (data) => (buf += data));
    pgrep_p.on("close", (code) => {
      if (code === 0) {
        const pid = buf.trim().split(/\r?\n/);
        if (pid.length !== 1) {
          return reject(`Found multiple processes for ${host}`);
        } else {
          return resolve(pid[0]);
        }
      } else {
        reject(code);
      }
    });
  });
}
