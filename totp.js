const HOTP = require('./hotp');

class TOTP extends HOTP {
	constructor({ key, algorithm='sha256', period=30 }) {
		super({ key, algorithm });
		this.period = period;
	}

	compute_counter(counter=Math.round(Date.now() / 1000)) {
		// TODO: handle timezones
		const seconds_since_epoch = counter;
		const number_of_periods = Math.floor(seconds_since_epoch / this.period);

		return super.compute_counter(number_of_periods);
	}

	// redefined to change counter argument name
	code({ digits, date=new Date(), algorithm, key }={}) {
		const counter = date instanceof Date ? Math.round(date.getTime() / 1000) : date;
		if(!Number.isInteger(counter)) {
			// We use seconds to respect the spec
			throw new Error('Date must be an integer in seconds');
		}

		return super.code({
			digits,
			counter,
			algorithm,
			key
		});
	}
}

module.exports = TOTP;
