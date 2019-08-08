const NS_PER_SEC = Math.pow(10, 9);

const os         = require("os");
const raw        = require("raw-socket");
const pcap       = require("pcap");
const types      = require("./types");

exports.ping = (...args) => {
	var ip_address = "00:00:00:00:00:00";
	var options    = {};
	var next       = noop;

	args.map((arg) => {
		switch (typeof arg) {
			case "string":
				ip_address = arg;
				break;
			case "object":
				options = arg;
				break;
			case "function":
				next = arg;
				break;
		}
	});

	options.tpa = ip_address;

	let packet = exports.build(options);

	try_ping(ip_address, packet, {
		tries    : options.tries    ||    3,
		interval : options.interval || 1000,
	}, next);
};

/**
 * Build an ARP packet. You can change properties from the packet
 * but you have to at least provide the target address
 *
 * Available options:
 *
 * - htype: hardware type               (default = Ethernet)
 * - sha: source hardware address       (default = runtime lookup)
 * - tha: target hardware address       (default = none)
 * - ptype: protocol type               (default = IPv4)
 * - spa: source protocol address       (default = runtime lookup)
 * - tpa: target protocol address       (default = none)
 *
 * @param   options                     Object with packet properties
 **/
exports.build = (options) => {
	if (typeof options.htype == "undefined")  options.htype = types.Ethernet;
	if (typeof options.ptype == "undefined")  options.ptype = types.IPv4;

	let offset = 14;
	let buffer = Buffer.alloc(offset + 8 + (options.htype.length * 2) + (options.ptype.length * 2));
	let iface  = null;

	buffer[0] = 0xFF;
	buffer[1] = 0xFF;
	buffer[2] = 0xFF;
	buffer[3] = 0xFF;
	buffer[4] = 0xFF;
	buffer[5] = 0xFF;

	buffer.writeUInt16BE(0x0806,               offset - 2); // ARP

	buffer.writeUInt16BE(options.htype.id,     offset + 0);
	buffer.writeUInt16BE(options.ptype.id,     offset + 2);
	buffer.writeUInt8   (options.htype.length, offset + 4);
	buffer.writeUInt8   (options.ptype.length, offset + 5);

	buffer.writeUInt16BE(0x0001,               offset + 6); // Request

	offset += 8;

	if (typeof options.sha == "undefined" || typeof options.spa == "undefined") {
		let ifaces = os.networkInterfaces();

		for (let dev in ifaces) {
			for (let i = 0; i < ifaces[dev].length; i++) {
				if (ifaces[dev][i].family != options.ptype.family) continue;

				if (typeof options.sha == "undefined" && typeof options.spa == "undefined") {
					if (ifaces[dev][i].internal) continue;
				} else if (typeof options.sha == "undefined") {
					if (ifaces[dev][i][options.ptype.interface_key] != options.spa) continue;
				} else if (typeof options.spa == "undefined") {
					if (ifaces[dev][i][options.htype.interface_key] != options.sha) continue;
				}

				iface = ifaces[dev][i];
				break;
			}

			if (iface !== null) break;
		}

		if (iface === null) throw new Error("Cannot find a suitable interface");

		buffer.writeUIntBE(options.htype.toNumber(iface[options.htype.interface_key]), 6, 6);

		buffer.writeUIntBE(options.htype.toNumber(iface[options.htype.interface_key]), offset, options.htype.length);
		offset += options.htype.length;

		buffer.writeUIntBE(options.ptype.toNumber(iface[options.ptype.interface_key]), offset, options.ptype.length);
		offset += options.ptype.length;
	} else {
		buffer.writeUIntBE(options.htype.toNumber(options.sha), 6, 6);

		buffer.writeUIntBE(options.htype.toNumber(options.sha), offset, options.htype.length);
		offset += options.htype.length;

		buffer.writeUIntBE(options.ptype.toNumber(options.spa), offset, options.ptype.length);
		offset += options.ptype.length;
	}

	if (typeof options.tha != "undefined") {
		buffer.writeUIntBE(options.htype.toNumber(options.tha), offset, options.htype.length);
	}
	offset += options.htype.length;

	if (typeof options.tpa != "undefined") {
		buffer.writeUIntBE(options.ptype.toNumber(options.tpa), offset, options.ptype.length);
	}
	offset += options.ptype.length;;

	return buffer;
};

function try_ping(ip_address, packet, options, next) {
	var has_done = false;
	var done     = (err, info) => {
		if (has_done) return;

		has_done = true;

		if (err) {
			options.tries -= 1;

			if (options.tries <= 0) return next(err);

			return try_ping(ip_address, packet, options, next);
		}

		return next(null, info);
	};

	let session = pcap.createSession("", "arp");
	let time    = process.hrtime();

	session.on("packet", (raw) => {
		var packet = pcap.decode.packet(raw);

		if (packet.payload.payload.sender_pa.toString() != ip_address) return;

		time = process.hrtime(time);

		return done(null, {
			elapsed : time[0] + time[1] / NS_PER_SEC,
			tha     : packet.payload.payload.target_ha.toString(),
			sha     : packet.payload.payload.sender_ha.toString(),
			tip     : packet.payload.payload.target_pa.toString(),
			sip     : packet.payload.payload.sender_pa.toString(),
		});
	});

	session.on("end", function(session) {
		session.close();
		session = null;
	});

	session.inject(packet);

	setTimeout(() => {
		if (!session) return;

		session.close();

		done(new Error("Timeout"));
	}, options.interval);
}

function noop() {}
