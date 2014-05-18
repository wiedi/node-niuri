"use strict"

function luhn16(input) {
	var sum = 0
	input.split('').reverse().forEach(function (c, index) {
		var m = (index + 1) % 2 + 1
		var t = parseInt(c, 16) * m
		sum += t
		if(t >= 16)
			sum++
	})
	return (16 - (sum % 16)).toString(16)
}

module.exports = luhn16