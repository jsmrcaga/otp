const Crypto = require('crypto');

class HOTP {
	constructor({ key, counter=0, algorithm='sha1' }={}) {
		this.key = key;
		this.counter = counter;
		this.algorithm = algorithm;
	}

	compute_counter(count) {
		if(!Number.isInteger(count)) {
			throw new Error('Count must be an integer');
		}
		// Counter is always 8 bytes
		// https://superuser.com/a/1506539

		// We alloc 8 bytes
		// we create a buffer from the INT value
		const counter_bytes = Buffer.alloc(8);
		counter_bytes.writeBigInt64BE(BigInt(count));

		// return eight byte buffer
		return counter_bytes;
	}

	compute_hmac({ algorithm=this.algorithm, key=this.key, counter }) {
		if(!(counter instanceof Buffer)) {
			throw new Error('Counter must be a buffer containing the int representation of the counter');
		}

		const hmac = Crypto.createHmac(algorithm, key);
		// update hmac with the counter and immediately update
		// please note that the cunter is a buffer
		hmac.update(counter);

		// get digest in buffer format
		const digest = hmac.digest();
		return digest;
	}

	truncate(bytes) {
		// https://datatracker.ietf.org/doc/html/rfc4226#section-5.4

		// Last byte
		// for sha1 this will be index 19
		const last_byte = bytes[bytes.length - 1];

		// Mask to 4 bits (0xF = 15 = b1111)
		const offset = last_byte & 0xF;

		// masks
		// we extract the last 31 bits of the code
		// the code being the 4 bytes of the hash

		// mask to 127 = b111 1111 = 7 bits
		const code = (bytes[offset] & 0x7F) << 24
			| (bytes[offset + 1] & 0xFF) << 16
			| (bytes[offset + 2] & 0xFF) << 8
			| (bytes[offset + 3] & 0xFF);

		return code;
	}

	modulo(code, digits=6) {
		return code % (10 ** digits);
	}

	code({ digits=6, counter=0, algorithm=this.algorithm, key=this.key }={}) {
		const _8byte_count = this.compute_counter(counter);
		const digest = this.compute_hmac({ algorithm, key, counter: _8byte_count });
		const code = this.truncate(digest);
		const modulo_10_digits = this.modulo(code, digits);
		return modulo_10_digits.toString().padStart(digits, '0');
	}
}

module.exports = HOTP;
