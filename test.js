"use strict"

var assert = require("assert")
var niuri  = require('./main')
var luhn16 = require('./luhn16')

suite('ParseBinary')

test('#rfc_example4', function() {
	var ni = niuri.parse(Buffer([
		0x03, 0x53, 0x26, 0x90, 0x57, 0xe1, 0x2f, 0xe2,
		0xb7, 0x4b, 0xa0, 0x7c, 0x89, 0x25, 0x60, 0xa2
	]))
	assert.equal(ni.algorithm, "sha-256-120")
	assert.equal(ni.hashvalue.toString("hex"), "53269057e12fe2b74ba07c892560a2")
})

test("#unsupported_suite", function() {
	assert.throws(
		function() {
			niuri.parse(Buffer([0x00, 0x00, 0x00]))
		}
	)
	assert.throws(
		function() {
			niuri.parse(Buffer([0x20, 0x00, 0x00]))
		}
	)
})
test("#ignore_header_flags", function() {
	assert.equal(niuri.parse(Buffer([0x06, 0x0, 0x0, 0x0, 0x0])).algorithm, "sha-256-32")
	assert.equal(niuri.parse(Buffer([0x46, 0x0, 0x0, 0x0, 0x0])).algorithm, "sha-256-32")
	assert.equal(niuri.parse(Buffer([0x86, 0x0, 0x0, 0x0, 0x0])).algorithm, "sha-256-32")
	assert.equal(niuri.parse(Buffer([0xc6, 0x0, 0x0, 0x0, 0x0])).algorithm, "sha-256-32")
})

suite('ParseURI')

test('#rfc_example1', function() {
	var ni = niuri.parse("ni:///sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q")
	assert.equal(ni.algorithm, "sha-256")
	assert.equal(ni.hashvalue.toString("hex"), "53269057e12fe2b74ba07c892560a2d753877eb62ff44d5a19002530ed97ffe4")
})

test('#rfc_example2_http', function() {
	var ni = niuri.parse("http://example.com/.well-known/ni/sha256/UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q")
	assert.equal(ni.algorithm, "sha256")
	assert.equal(ni.hashvalue.toString("hex"), "53269057e12fe2b74ba07c892560a2d753877eb62ff44d5a19002530ed97ffe4")
	assert.equal(ni.authority, "example.com")
})

test('#rfc_example2_https', function() {
	var ni = niuri.parse("https://example.com/.well-known/ni/sha256/UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q")
	assert.equal(ni.algorithm, "sha256")
	assert.equal(ni.hashvalue.toString("hex"), "53269057e12fe2b74ba07c892560a2d753877eb62ff44d5a19002530ed97ffe4")
	assert.equal(ni.authority, "example.com")
})

test('#rfc_example5_nih', function() {
	var ni = niuri.parse("nih:sha-256-120;5326-9057-e12f-e2b7-4ba0-7c89-2560-a2;f")
	assert.equal(ni.algorithm, "sha-256-120")
	assert.equal(ni.hashvalue.toString("hex"), "53269057e12fe2b74ba07c892560a2")
})

test('#rfc_example6_nih', function() {
	var ni = niuri.parse("nih:sha-256-32;53269057;b")
	assert.equal(ni.algorithm, "sha-256-32")
	assert.equal(ni.hashvalue.toString("hex"), "53269057")
})

test('#rfc_example7_nih', function() {
	var ni = niuri.parse("nih:3;532690-57e12f-e2b74b-a07c89-2560a2;f")
	assert.equal(ni.algorithm, "sha-256-120")
	assert.equal(ni.hashvalue.toString("hex"), "53269057e12fe2b74ba07c892560a2")
})

test('#nih_without_checkdigit', function() {
	var ni = niuri.parse("nih:3;532690-57e12f-e2b74b-a07c89-2560a2")
	assert.equal(ni.algorithm, "sha-256-120")
	assert.equal(ni.hashvalue.toString("hex"), "53269057e12fe2b74ba07c892560a2")
})

test('#invalid_checkdigit', function() {
	assert.throws(
		function() {
			niuri.parse("nih:3;532690-57e12f-e2b74b-a07c89-2560a2;a")
		}
	)
})

suite('Luhn16')
test('#known_vectors', function() {
	assert.equal(luhn16("a8b56f"), 'b')
	assert.equal(luhn16("53269057"), 'b')
	assert.equal(luhn16("53269057e12fe2b74ba07c892560a2"), 'f')
})

suite('Format')

test('#reproduce', function() {
	var uri = "nih:sha-256-120;5326-9057-e12f-e2b7-4ba0-7c89-2560-a2;f"
	var ni = niuri.parse(uri)
	assert.equal(ni.format('nih'), uri)
})

test('#format', function() {
	var ni = new niuri.NI('sha-256-120', Buffer("53269057e12fe2b74ba07c892560a2", "hex"))
	assert.equal(ni.format('ni'), "ni:///sha-256-120;UyaQV+Ev4rdLoHyJJWCi")
	ni.authority = "example.com"
	assert.equal(ni.format('ni'),    "ni://example.com/sha-256-120;UyaQV+Ev4rdLoHyJJWCi")
	assert.equal(ni.format('http'),  "http://example.com/.well-known/ni/sha-256-120/UyaQV+Ev4rdLoHyJJWCi")
	assert.equal(ni.format('https'), "https://example.com/.well-known/ni/sha-256-120/UyaQV+Ev4rdLoHyJJWCi")
})

suite('GenerateBinary')

test('#toBuffer', function() {
	var buf = Buffer([
		0x03, 0x53, 0x26, 0x90, 0x57, 0xe1, 0x2f, 0xe2,
		0xb7, 0x4b, 0xa0, 0x7c, 0x89, 0x25, 0x60, 0xa2
	])
	var ni = niuri.parse(buf)
	assert.equal(ni.toBuffer().toString('hex'), buf.toString('hex'))
})