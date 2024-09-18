<?php
// Load the service account JSON file
$serviceAccountPath='https://t.ly/c5sZO'; 
$serviceAccount = json_decode(file_get_contents($serviceAccountPath), true);
// Extract information from the service account JSON
$clientEmail = $serviceAccount ['client_email'];
$privateKey = $serviceAccount ['private_key'];
// Define JWT header and payload
$header = json_encode(['alg' => 'RS256', 'typ' => 'JWT']);
$now = time();
$expiration = $now + 3600; // 1 hour expiration
$payload= json_encode([
'iss' => $clientEmail,
'scope' => 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/firebase.messaging',
'aud' => 'https://oauth2.googleapis.com/token',
'exp' => $expiration,
'iat' => $now
]);

// Encode to base64
$base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header)); 
$base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload)); 
// Create the signature
$signatureInput = $base64UrlHeader . "." . $base64UrlPayload;
openssl_sign($signatureInput, $signature, $privateKey, 'sha256');
$base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
// Create the JWT

$jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
// Exchange JWT for an access token
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://oauth2.googleapis.com/token');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);

curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    'assertion' => $jwt
]));

$response = curl_exec($ch);
curl_close($ch);
$responseData = json_decode($response, true);
// Error debugging team

$response = curl_exec($ch);
if (curl_errno($ch)) {
  $error = curl_error($ch);
  echo "Error during cURL request: $error";
  curl_close($ch);
  exit;
}
curl_close($ch);
// closing the debugging
$accessToken = $responseData['access_token'];
// Define the notification payload
$notification = [
'message' => [
'token' => 'dfFyxKnygRIICH25nQt1uh:APA91bF4wuFuhPBYA4UwLTHR_nF1i5pltUsEflje_AgvGckUD0a3nIsJDpNVYVMS-lNCTlizyRrawEFhVU6vvPD3d-Pge5sexlzVzeYrwPb2XUF-HcLAKhj4syWJrC9jRZ2ApvDaZoVV',
'notification' => [
    'title' => 'Hello', 
    'body' => 'World'
]]];
// Send the push notification 
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://fcm.googleapis.com/v1/projects/webtoolkit02/messages:send');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [    
    'Authorization: Bearer' . $accessToken,
    'Content-Type: application/json' 
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($notification));
$response = curl_exec($ch);
curl_close($ch);
echo $response;
?>
