"use strict"

var url    = require('url')
var luhn16 = require('./luhn16')

exports.parse = parse
exports.NI = NI

/* See Figure 11 in rfc6920 */
var suites = {
	1: {name: 'sha-256',     length: 32},
	2: {name: 'sha-256-128', length: 16},
	3: {name: 'sha-256-120', length: 15},
	4: {name: 'sha-256-96',  length: 12},
	5: {name: 'sha-256-64',  length:  8},
	6: {name: 'sha-256-32',  length:  4}
}

function getID(name) {
	return Number(Object.keys(suites).filter(function(key) {
		return suites[key].name === name})[0])
}

function NI(algorithm, hashvalue, authority) {
	this.algorithm = algorithm || null
	this.hashvalue = hashvalue || null
	this.authority = authority || null
}

function parse(url) {
	if (url && url instanceof NI) return url;
	var ni = new NI()
	ni.parse(url)
	return ni
}

NI.prototype.parse = function(uri) {
	if(Buffer.isBuffer(uri)) {
		var header = uri.readUInt8(0)
		var algorithm_id = header & 0x3f
		if(!(algorithm_id in suites)) {
			throw new Error("Unsupported Suite ID: " + algorithm_id)
		}
		this.algorithm = suites[algorithm_id].name
		var length = suites[algorithm_id].length
		this.hashvalue = Buffer(length)
		if(uri.length < length + 1) {
			throw new Error("Hash Value too short for " + this.algorithm)
		}
		uri.copy(this.hashvalue, 0, 1, suites[algorithm_id].length + 1)
	} else if (typeof uri === "string") {
		var u = url.parse(uri)
		if(u.protocol == 'ni:') {
			if(u.pathname[0] != '/') {
				throw new Error("Invalid URI")
			}
			var path = u.pathname.slice(1)
			var path_slices = path.split(";")
			if(path_slices.length != 2) {
				throw new Error("Invalid URI")
			}
			this.algorithm = path_slices[0]
			this.hashvalue = Buffer(path_slices[1], 'base64')
		} else if(u.protocol == 'nih:') {
			var algorithm_id = parseInt(u.hostname)
			if(algorithm_id in suites) {
				this.algorithm = suites[algorithm_id].name
			} else {
				this.algorithm = u.hostname
			}

			if(u.pathname[0] != ';') {
				throw new Error("Invalid URI")
			}
			var path = u.pathname.slice(1)

			var path_slices = path.split(";")
			if(path_slices.length > 2) {
				throw new Error("Invalid URI")
			}

			this.hashvalue = Buffer(path_slices[0].replace(/-/g,''), 'hex')

			if(path_slices.length > 1) {
				if(luhn16(this.hashvalue.toString('hex')) != path_slices[1]) {
					throw new Error("Checkdigit does not match.")
				}
			}
		} else if(u.protocol == 'http:' || u.protocol == 'https:') {
			var prefix = "/.well-known/ni/"
			if(u.path.lastIndexOf(prefix, 0) !== 0) {
				throw new Error("Not a well-known Named Information URI")
			}
			var path = u.pathname.slice(prefix.length)
			var path_slices = path.split("/")
			if(path_slices.length != 2) {
				throw new Error("Invalid URI")
			}
			this.algorithm = path_slices[0]
			this.hashvalue = Buffer(path_slices[1], 'base64')
			this.authority = u.hostname
		} else {
			throw new Error("Not a Named Information URI")
		}
	} else {
		throw new TypeError("First parameter must be a string or buffer, not " + typeof uri);
	}
}

NI.prototype.format = function(scheme) {
	switch(scheme) {
	case 'http':
	case 'http:':
	case 'https':
	case 'https:':
		return url.format({
			protocol: scheme,
			hostname: this.authority || 'localhost',
			pathname: "/.well-known/ni/" + this.algorithm + "/" +
				this.hashvalue.toString('base64').replace(/=/g, '')
		})
	case 'nih':
	case 'nih:':
		var hash = this.hashvalue.toString('hex')
		return url.format({
			protocol: 'nih',
			hostname: this.algorithm,
			pathname: ';' + hash.match(/.{1,4}/g).join('-') + ';' + luhn16(hash)
		})
	case 'ni':
	case 'ni:':
	default:
		return url.format({
			protocol: 'ni',
			slashes: true,
			hostname: this.authority || '',
			pathname: this.algorithm + ';' + this.hashvalue.toString('base64').replace(/=/g, '')
		})
	}
}

NI.prototype.toBuffer = function() {
	var id = getID(this.algorithm)
	var buf = new Buffer(suites[id].length + 1)
	buf[0] = id
	this.hashvalue.copy(buf, 1)
	return buf
}

NI.prototype.digest = function(encoding) {
	return this.hashvalue.digest(encoding)
}

NI.prototype.equal = function(other) {
	return (
		this.algorithm     == other.algorithm &&
		this.digest('hex') == other.digest('hex')
	)
}