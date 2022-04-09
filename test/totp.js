const TOTP = require('../totp');

const { expect } = require('chai');

describe('TOTP', () => {
	describe('RFC 6238 examples', () => {
		const rfc_example_secret = '12345678901234567890';

		const SECRETS = {
			// This is not visible on the spec, you must look at their example
			// code to see that the keys change between digest algorithms
			'SHA1': '12345678901234567890',
			'SHA256': '12345678901234567890123456789012',
			'SHA512': '1234567890123456789012345678901234567890123456789012345678901234'
		};

		for(const [date, expected, algorithm] of [
			['1970-01-01T00:00:59Z', '94287082', 'SHA1'],
			['1970-01-01T00:00:59Z', '46119246', 'SHA256'],
			['1970-01-01T00:00:59Z', '90693936', 'SHA512'],
			['2005-03-18T01:58:29Z', '07081804', 'SHA1'],
			['2005-03-18T01:58:29Z', '68084774', 'SHA256'],
			['2005-03-18T01:58:29Z', '25091201', 'SHA512'],
			['2005-03-18T01:58:31Z', '14050471', 'SHA1'],
			['2005-03-18T01:58:31Z', '67062674', 'SHA256'],
			['2005-03-18T01:58:31Z', '99943326', 'SHA512'],
			['2009-02-13T23:31:30Z', '89005924', 'SHA1'],
			['2009-02-13T23:31:30Z', '91819424', 'SHA256'],
			['2009-02-13T23:31:30Z', '93441116', 'SHA512'],
			['2033-05-18T03:33:20Z', '69279037', 'SHA1'],
			['2033-05-18T03:33:20Z', '90698825', 'SHA256'],
			['2033-05-18T03:33:20Z', '38618901', 'SHA512'],
			['2603-10-11T11:33:20Z', '65353130', 'SHA1'],
			['2603-10-11T11:33:20Z', '77737706', 'SHA256'],
			['2603-10-11T11:33:20Z', '47863826', 'SHA512']
		]) {
			it(`Should get the correct code depending on date and algo (${date}, ${algorithm})`, () => {
				const totp = new TOTP({
					key: SECRETS[algorithm],
					algorithm
				});

				const code = totp.code({
					date: new Date(date),
					digits: expected.length
				});

				expect(code).to.be.eql(expected);
			});
		}
	});
});
