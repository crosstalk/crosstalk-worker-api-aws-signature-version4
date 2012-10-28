var ide = require( 'crosstalk-ide' )(),
    config = {},
    workerPath = require.resolve( 'crosstalk-worker-api-aws-signature-version4' );

var worker;

worker = ide.run( workerPath, { config : config } );

var validRequestSignature = {
  awsAccessKeyId : "KEYNAME",
  headers : {
    date : "Mon, 09 Sep 2011 23:36:00 GMT",
    host : "host.foo.com"
  },
  queryString : "foo=Zoo&foo=aha",
  region : "us-west-1",
  service : "s3",
  secretAccessKey : "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
}; 

worker.send( 'api.aws.signature.version4', validRequestSignature );