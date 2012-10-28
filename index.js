/*
 * index.js : Crosstalk AWS version 4 signature generator
 *
 * (C) 2012 Crosstalk Systems Inc.
 */
"use strict";

var crypto = require( 'crypto' );

var ALGORITHM = "AWS4-HMAC-SHA256",
    CREDENTIAL_TERMINATION_STRING = "aws4_request",
    DEFAULT_CANONICAL_URI = "/",
    DEFAULT_HTTP_REQUEST_METHOD = "GET";

var createBasicISODate = function createBasicISODate ( date ) {

  // Basic ISO 8601 Date
  var basicISODate = date ? new Date( date ) : new Date();
  
  basicISODate = basicISODate.toISOString()
                    .replace( /-/g, '' )
                    .replace( /:/g, '' )
                    .replace( /\..*/, '' ) + "Z";

  return basicISODate;

}; // createBasicISODate

var createCanonicalHeaders = function createCanonicalHeaders ( headers ) {

  var canonicalHeaders = "",
      tempHeaders = {},
      lowercaseHeaders = [];

  Object.keys( headers ).forEach( function( header ) {

    lowercaseHeaders.push( header.toLowerCase() );
    tempHeaders[ header.toLowerCase() ] = headers[ header ];

  }); // Object.keys( headers ).forEach

  lowercaseHeaders.sort();

  lowercaseHeaders.forEach( function ( header ) {
    canonicalHeaders += header + ":" + trimall( tempHeaders[ header ] ) + "\n";
  }); // lowercaseHeader.forEach

  return canonicalHeaders;

}; // createCanonicalHeaders

var createCanonicalQueryString = function createCanonicalQueryString (
   queryString, credential, basicISODate, signedHeaders ) {
     
  var canonicalQueryString = "";

  queryString = queryString.split( '&' );
  queryString.sort();

  queryString.forEach( function ( pair ) {

    canonicalQueryString += "&";

    pair = pair.split( '=' );

    if ( ! pair || pair.length != 2 ) {
      return new Error( "invalid queryString format" );
    }

    // decode first just in case we have encoded component already
    canonicalQueryString += encodeURIComponent( decodeURIComponent( pair[ 0 ] ) );
    canonicalQueryString += "=";
    canonicalQueryString += encodeURIComponent( decodeURIComponent( pair[ 1 ] ) );

  }); // queryString.forEach

  // remove the first "&" we put
  canonicalQueryString = canonicalQueryString.slice( 1 );

  return canonicalQueryString;

}; // createCanonicalQueryString

var createCanonicalRequest = function createCanonicalRequest ( httpRequestMethod, 
   canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders,
   encodedPayload ) {

  return httpRequestMethod + "\n" +
         canonicalUri + "\n" +
         canonicalQueryString + "\n" +
         canonicalHeaders + "\n" +
         signedHeaders + "\n" +
         encodedPayload;

}; // createCanonicalRequest

var createCredential = function createCredential( awsAccessKeyId, 
   credentialScope ) {

  return awsAccessKeyId + "/" + credentialScope

}; // createCredential

var createCredentialScope = function createCredentialScope( basicISODate, 
   region, service ) {

  return basicISODate.replace( /T.*/, '' ) + "/" + region.toLowerCase() + "/" + 
     service.toLowerCase() + "/" + CREDENTIAL_TERMINATION_STRING;

}; // createCredentialScope

var hexEncodeHash = function hexEncodeHash ( body ) {

  body = body || ''

  return crypto.createHash( 'sha256' ).update( body ).digest( 'hex' );

}; // hexEncodeHash

var createSignedHeaders = function createSignedHeaders ( headers ) {

  var lowercaseHeaders = [];

  Object.keys( headers ).forEach( function ( header ) {
    lowercaseHeaders.push( header.toLowerCase() );
  });

  return lowercaseHeaders.sort().join( ';' );

}; // createSignedHeaders

var createStringToSign = function createStringToSign ( algorithm, requestDate,
   credentialScope, canonicalRequest ) {

  return algorithm + "\n" +
     requestDate + "\n" +
     credentialScope + "\n" +
     hexEncodeHash( canonicalRequest );

}; // createStringToSign

var hmac = function hmac( key, stringToSign, format ) {

  return crypto.createHmac( 'sha256', key ).update( stringToSign )
    .digest( format );

}; // hmac

var trimall = function trimall ( string ) {

  string = string || "";

  var trimmedString = "",
      parts = string.split( '"' ),
      quoteToggle = 1;

  parts.forEach( function ( part ) {

    if ( quoteToggle % 2) {
      trimmedString += part.replace( /\s+/g, ' ' );
    } else {
      trimmedString += '"' + part + '"';
    }

    quoteToggle++;

  }); // parts.forEach

  return trimmedString.trim();

}; // trimall

var version4 = function version4 ( params, callback ) {

  if ( ! callback ) { return; } // nothing to do

  //
  // required params
  //
  var awsAccessKeyId = params.awsAccessKeyId,
      headers = params.headers,
      queryString = params.queryString,
      region = params.region,
      secretAccessKey = params.secretAccessKey,
      service = params.service;

  if ( ! awsAccessKeyId ) return callback( { message : "missing awsAccessKeyId" } );
  if ( ! headers ) return callback( { message : "missing headers" } );
  if ( ! queryString ) return callback( { message : "missing queryString" } );
  if ( ! region ) return callback( { message : "missing region" } );
  if ( ! secretAccessKey ) return callback( { message : "missing secretAccessKey" } );
  if ( ! service ) return callback( { message : "missing service" } );

  //
  // optional params
  //
  var body = params.body,
      canonicalUri = params.canonicalUri || DEFAULT_CANONICAL_URI,
      httpRequestMethod = params.httpRequestMethod 
         || DEFAULT_HTTP_REQUEST_METHOD;

  //
  // Task 1: Create a Canonical Request
  // http://docs.amazonwebservices.com/general/latest/gr/sigv4-create-canonical-request.html
  //

  var basicISODate;

  // add date if it is not present
  var dateHeaderValue = null;
  
  Object.keys( headers ).forEach( function ( header ) {
    if ( header.toLowerCase() == "date" ) dateHeaderValue = headers[ header ];
  });

  if ( ! dateHeaderValue ) {

    basicISODate = createBasicISODate();
    headers[ 'X-Amz-Date' ] = basicISODate;

  } else {
    basicISODate = createBasicISODate( dateHeaderValue );
  }

  var canonicalHeaders = createCanonicalHeaders( headers );
  var signedHeaders = createSignedHeaders( headers );

  var credentialScope = createCredentialScope( basicISODate, region, service );
  var credential = createCredential( awsAccessKeyId, credentialScope );
  var canonicalQueryString = createCanonicalQueryString( queryString, 
     credential, basicISODate, signedHeaders );

  if ( typeof( canonicalQueryString ) == "object" ) { // got error
    return callback( { message : canonicalQueryString.message } );
  }

  var encodedPayload = hexEncodeHash( body );

  var canonicalRequest = createCanonicalRequest( httpRequestMethod, 
     canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders,
     encodedPayload );

  //
  // Task 2: Create a String to Sign
  // http://docs.amazonwebservices.com/general/latest/gr/sigv4-create-string-to-sign.html
  // 

  var stringToSign = createStringToSign( ALGORITHM, basicISODate,
     credentialScope, canonicalRequest );

  //
  // Task 3: Calculate the Signature
  // http://docs.amazonwebservices.com/general/latest/gr/sigv4-calculate-signature.html
  //

  var kSecret = secretAccessKey;
  var kDate = hmac( "AWS4" + kSecret, basicISODate.replace( /T.*/, '' ), 
     'binary' );
  var kRegion = hmac( kDate, region, 'binary' );
  var kService = hmac( kRegion, service, 'binary' );
  var kSigning = hmac( kService, CREDENTIAL_TERMINATION_STRING, 'binary' );

  var signature = hmac( kSigning, stringToSign, 'hex' );

  var authorization = ALGORITHM + " Credential=" + credential + 
     ",SignedHeaders=" + signedHeaders + ",Signature=" + signature;

  return callback( null, {
    algorithm : ALGORITHM,
    authorization : authorization,
    credential : credential,
    date : basicISODate,
    signature : signature,
    signedHeaders : signedHeaders
  });

}; // version4

crosstalk.on( 'api.aws.signature.version4', 'public', version4 );