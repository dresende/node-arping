exports.Ethernet = new Type(0x0001, "Ethernet", "mac",  6, ":", 16);
exports.IPv4     = new Type(0x0800, "IPv4", "address",  4, ".", 10);

function Type(id, family, key, len, sep, base) {
	this.id            = id;
	this.family        = family;
	this.length        = len;
	this.separator     = sep;
	this.string_base   = base;
	this.interface_key = key;
}

Type.prototype.toNumber = function (address) {
	address = address.split(this.separator);

	let buffer = Buffer.alloc(this.length);

	address.map((byte, index) => {
		buffer[this.length - address.length + index] = parseInt(byte, this.string_base);
	});

	return buffer.readUIntBE(0, buffer.length);
};
