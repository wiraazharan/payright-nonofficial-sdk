<?php

namespace Payright\PayrightUnofficialSdk;

use DateTime;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;
use stdClass;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

class PayrightUnofficialSdk
{
    protected $client;
    protected $authToken;
    protected $baseUrl;
    protected $hashKey;
    protected $UUID;

    public function __construct(string $baseUrl, string $authToken, string $hashKey, string $UUID)
    {
        $this->authToken = $authToken;
        $this->hashKey = $hashKey;
        $this->UUID = $UUID;
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->client = new Client();
    }

    //NON HMAC ENDPOINTS;
    public function GeneratePaymentLinkv1(array $parameters)
    {
        $URLPATH = "/api/v1/merchant/bills";
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;

        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
        ];

        $body = $parameters;
        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    public function CheckPaymentStatusV1(string $invoiceNo)
    {
        $URLPATHFORSIGNATURE = "/api/v1/merchant/bills";
        $URLPATH = "/api/v1/merchant/bills/{$invoiceNo}";
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;

        //GENERATE SIGNATURE
        $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
        //GENERATE SIGNATURE

        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
        ];

        $body = [];
        $response = json_decode($this->PostRequestLeanx($endpoint, $header, $body));
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    public function GetPaymentServices(array $parameters)
    {
        $URLPATH = "/api/v1/merchant/list-payment-provider";
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;

        // Prepare the request headers
        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
        ];

        // Prepare the request body
        $body = $parameters;

        // Make the POST request and get the response
        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

        // Prepare and return the response details
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    //NON HMAC ENDPOINTS;

    //HMAC ENDPOINTS;
    public function GeneratePaymentLinkv1WithHashmac(array $parameters)
    {
        $URLPATHFORSIGNATURE = "/api/v1/merchant/bills";
        $URLPATH = "/api/v1/merchant/bills";
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;

        //GENERATE SIGNATURE
        $signatures = $this->GenerateJwtTokenForRequestSignature($this->hashKey, $this->authToken, $HTTPMETHOD, $URLPATHFORSIGNATURE);
        //GENERATE SIGNATURE

        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
            'x-signature' => $signatures,
            // 'x-timestamp' => $signatures["x-timestamp"],
            // 'x-nonce' => $signatures["x-nonce"],
        ];

        $body = $parameters;

        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));
        $responses = [
            // "url" => $endpoint,
            // "signature" => $signatures,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    public function CheckPaymentStatusV1WithHmac(string $invoiceNo)
    {
        $URLPATHFORSIGNATURE = "/api/v1/merchant/bills/{$invoiceNo}";
        $URLPATH = "/api/v1/merchant/bills/{$invoiceNo}";
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;

        //GENERATE SIGNATURE
        $signatures = $this->GenerateJwtTokenForRequestSignature($this->hashKey, $this->authToken, $HTTPMETHOD, $URLPATHFORSIGNATURE);
        //GENERATE SIGNATURE

        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
            'x-signature' => $signatures
        ];

        $body = [];
        $response = json_decode($this->PostRequestLeanx($endpoint, $header, $body));
        $responses = [
            // "url" => $endpoint,
            // "signature" => $signatures,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    public function GetPaymentServicesHmac(array $parameters)
    {
        $URLPATHFORSIGNATURE = "/api/v1/merchant/list-payment-provider";
        $URLPATH = "/api/v1/merchant/list-payment-provider";
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;

        //GENERATE SIGNATURE
        $signatures = $this->GenerateJwtTokenForRequestSignature($this->hashKey, $this->authToken, $HTTPMETHOD, $URLPATHFORSIGNATURE);
        //GENERATE SIGNATURE

        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
            'x-signature' => $signatures
        ];

        // Prepare the request body
        $body = $parameters;

        // Make the POST request and get the response
        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

        // Prepare and return the response details
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    //HMAC ENDPOINTS;

    //JOIN ENDPOINTS
    // public function GetPoolBalance(array $parameters = [], $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/overall-balance";
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH;

    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/overall-balance";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function CreateCollection(array $parameters = [], $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/create-payment-collection";
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH;

    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/create-payment-collection";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function GetCollectionList($parameters, $skip, $limit, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/collection-list";
    //     $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH . $QUERYSTRING;

    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/collection-list";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function GetSpecificCollection($collectionId, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/payment-collection";
    //     // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/payment-collection";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     $parameters = [
    //         "_id" => $collectionId
    //     ];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function UpdateCollection($parameters, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/update-payment-collection";
    //     // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "PUT";
    //     $endpoint = $this->baseUrl . $URLPATH;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/update-payment-collection";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PutRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function ActivateCollection($collectionId, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/activate-payment-collection";
    //     // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/activate-payment-collection";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     $parameters = [
    //         "_id" => $collectionId
    //     ];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PutRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function DeactivateCollection($collectionId, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/deactivate-payment-collection";
    //     // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "PUT";
    //     $endpoint = $this->baseUrl . $URLPATH;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/deactivate-payment-collection";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     $parameters = [
    //         "_id" => $collectionId
    //     ];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PutRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function TransactionList($skip, $limit, $startDate = "01-01-1970", $endDate = "31-01-2099", $invoiceStatus = "SUCCESS", $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/transaction-list";
    //     // ?skip=0&limit=10&start_date=01-01-1970&end_date=31-01-2099
    //     $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit . "&start_date=" . $startDate . "&end_date=" . $endDate . "&invoice_status=" . $invoiceStatus;
    //     $HTTPMETHOD = "GET";
    //     $endpoint = $this->baseUrl . $URLPATH . $QUERYSTRING;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/transaction-list";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     $parameters = [];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->GetRequestMam($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    public function PayoutServiceList($parameters = [], $useHmac = false)
    {
        $URLPATH = "/api/v1/merchant/list-payout-providers";
        // ?skip=0&limit=10&start_date=01-01-1970&end_date=31-01-2099
        // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit . "&start_date=" . $startDate . "&end_date=" . $endDate . "&invoice_status=" . $invoiceStatus;
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;
        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
        ];

        if ($useHmac) {
            //GENERATE SIGNATURE
            $URLPATHFORSIGNATURE = "/api/v1/merchant/list-payout-providers";
            $signatures = $this->GenerateJwtTokenForRequestSignature($this->hashKey, $this->authToken, $HTTPMETHOD, $URLPATHFORSIGNATURE);
            //GENERATE SIGNATURE

            $header = [
                'x-signature' => $signatures
            ];
        }

        // $parameters = [];
        // Prepare the request body
        $body = $parameters;

        // Make the POST request and get the response
        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

        // Prepare and return the response details
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    // public function PayoutTransactionList($parameters, $skip, $limit, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/payout-transaction-list";
    //     // ?skip=0&limit=10&start_date=01-01-1970&end_date=31-01-2099
    //     // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit . "&start_date=" . $startDate . "&end_date=" . $endDate . "&invoice_status=" . $invoiceStatus;
    //     $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH . $QUERYSTRING;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/payout-transaction-list";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // $parameters = [];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    public function CreatePayout($parameters, $useHmac = false)
    {
        $URLPATH = "/api/v1/merchant/payout";
        // ?skip=0&limit=10&start_date=01-01-1970&end_date=31-01-2099
        // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit . "&start_date=" . $startDate . "&end_date=" . $endDate . "&invoice_status=" . $invoiceStatus;
        // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;
        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
        ];

        if ($useHmac) {
            //GENERATE SIGNATURE
            $URLPATHFORSIGNATURE = "/api/v1/merchant/payout";
            $signatures = $this->GenerateJwtTokenForRequestSignature($this->hashKey, $this->authToken, $HTTPMETHOD, $URLPATHFORSIGNATURE);
            //GENERATE SIGNATURE

            $header = [
                'x-signature' => $signatures
            ];
        }

        // $parameters = [];
        // Prepare the request body
        $body = $parameters;

        // Make the POST request and get the response
        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

        // Prepare and return the response details
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    public function PayoutStatus($invoiceNoOrExternalInvoiceRef, $useHmac = false)
    {
        $URLPATH = "/api/v1/merchant/payout/{$invoiceNoOrExternalInvoiceRef}";
        // ?skip=0&limit=10&start_date=01-01-1970&end_date=31-01-2099
        // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit . "&start_date=" . $startDate . "&end_date=" . $endDate . "&invoice_status=" . $invoiceStatus;
        $QUERYSTRING = "?_id=" . $invoiceNoOrExternalInvoiceRef;
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH . $QUERYSTRING;
        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
        ];

        if ($useHmac) {
            //GENERATE SIGNATURE
            $URLPATHFORSIGNATURE = "/api/v1/merchant/payout/{$invoiceNoOrExternalInvoiceRef}";
            $signatures = $this->GenerateJwtTokenForRequestSignature($this->hashKey, $this->authToken, $HTTPMETHOD, $URLPATHFORSIGNATURE);
            //GENERATE SIGNATURE

            $header = [
                'x-signature' => $signatures
            ];
        }

        $parameters = [];
        // Prepare the request body
        $body = $parameters;

        // Make the POST request and get the response
        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

        // Prepare and return the response details
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }
    public function BankAccountValidation($parameters, $useHmac = false)
    {
        $URLPATH = "/api/v1/merchant/check-verification-bank";
        // ?skip=0&limit=10&start_date=01-01-1970&end_date=31-01-2099
        // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit . "&start_date=" . $startDate . "&end_date=" . $endDate . "&invoice_status=" . $invoiceStatus;
        // $QUERYSTRING = "?_id=" . $invoiceNoOrExternalInvoiceRef;
        $HTTPMETHOD = "POST";
        $endpoint = $this->baseUrl . $URLPATH;
        $header = [
            'Content-Type' => 'application/json',
            'auth-token' => $this->authToken,
        ];

        if ($useHmac) {
            //GENERATE SIGNATURE
            $URLPATHFORSIGNATURE = "/api/v1/merchant/check-verification-bank";
            $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
            //GENERATE SIGNATURE

            $header = [
                'x-signature' => $signatures["x-signature"],
                'x-timestamp' => $signatures["x-timestamp"],
                'x-nonce' => $signatures["x-nonce"],
            ];
        }

        // $parameters = [];
        // Prepare the request body
        $body = $parameters;

        // Make the POST request and get the response
        $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

        // Prepare and return the response details
        $responses = [
            // "url" => $endpoint,
            // "header" => $header,
            // "body" => $body,
            "response" => $response,
        ];
        return $responses;
    }

    // public function GetBillList($parameters, $skip, $limit, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/bill-list";
    //     $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH . $QUERYSTRING;

    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/bill-list";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function GetSpecificBill($billId, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/bill-id";
    //     // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/bill-id";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     $parameters = [
    //         "_id" => $billId
    //     ];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function GetBillTransactionStatus($billNo, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/manual-checking-transaction";
    //     $QUERYSTRING = "?invoice_no=" . $billNo;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH . $QUERYSTRING;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/manual-checking-transaction";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     $parameters = [
    //         "_id" => $billNo
    //     ];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function CreateBill($parameters, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/create-bill-page";
    //     // $QUERYSTRING = "?invoice_no=" . $billNo;
    //     $HTTPMETHOD = "POST";
    //     $endpoint = $this->baseUrl . $URLPATH;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/create-bill-page";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // $parameters = [
    //     //     "_id" => $billNo
    //     // ];
    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PostRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    // public function UpdateBill($parameters, $useHmac = false)
    // {
    //     $URLPATH = "/api/v1/merchant/update-bill";
    //     // $QUERYSTRING = "?skip=" . $skip . "&limit=" . $limit;
    //     $HTTPMETHOD = "PUT";
    //     $endpoint = $this->baseUrl . $URLPATH;
    //     $header = [
    //         'Content-Type' => 'application/json',
    //         'auth-token' => $this->authToken,
    //     ];

    //     if ($useHmac) {
    //         //GENERATE SIGNATURE
    //         $URLPATHFORSIGNATURE = "/api/v1/merchant/update-bill";
    //         $signatures = $this->GenerateSignature($this->UUID, $this->authToken, $this->hashKey, $HTTPMETHOD, $URLPATHFORSIGNATURE);
    //         //GENERATE SIGNATURE

    //         $header = [
    //             'x-signature' => $signatures["x-signature"],
    //             'x-timestamp' => $signatures["x-timestamp"],
    //             'x-nonce' => $signatures["x-nonce"],
    //         ];
    //     }

    //     // Prepare the request body
    //     $body = $parameters;

    //     // Make the POST request and get the response
    //     $response = json_decode($this->PutRequestMamJsonBody($endpoint, $header, $body));

    //     // Prepare and return the response details
    //     $responses = [
    //         // "url" => $endpoint,
    //         // "header" => $header,
    //         // "body" => $body,
    //         "response" => $response,
    //     ];
    //     return $responses;
    // }
    //JOIN ENDPOINTS


    //DECODE CALLBACK
    public function DecodeCallback($payload)
    {
        $secretKey = $this->hashKey;
        try {
            // Decode the JWT using the provided secret key and algorithm
            $decoded = JWT::decode($payload, new Key($secretKey, 'HS256'));
            return (array) $decoded; // Convert the decoded object to an array
        } catch (ExpiredException $e) {
            // Handle expired token
            return ['error' => 'Token expired'];
        } catch (SignatureInvalidException $e) {
            // Handle invalid signature
            return ['error' => 'Invalid token signature'];
        } catch (\Exception $e) {
            // Handle other possible exceptions
            return ['error' => 'Invalid token: ' . $e->getMessage()];
        }
    }
    //DECODE CALLBACK



    //TOOLBOX
    protected function sendRequest(string $method, string $endpoint, array $parameters = [], bool $json = false)
    {
        $url = $this->baseUrl . $endpoint;

        $headers = [
            'auth-token' => $this->authToken,
            'Accept' => 'application/json'
        ];

        if ($json) {
            $headers['Content-Type'] = 'application/json';
            $body = $parameters;
        } else {
            $body = http_build_query($parameters);
        }

        $request = new Request($method, $url, $headers, $body);

        try {
            $response = $this->client->sendAsync($request)->wait();
            return json_decode($response->getBody(), true);
        } catch (RequestException $e) {
            return ['error' => $e->getMessage()];
        }
    }

    protected static function PostRequestMamPlainText($endpoint, $header = null, $body)
    {

        try {
            $curl = curl_init();

            curl_setopt_array($curl, array(
                CURLOPT_URL => $endpoint,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 0,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_SSL_VERIFYPEER => 0,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => $header,
            ));

            $response = curl_exec($curl);

            curl_close($curl);

            return $response;
        } catch (Exception $e) {
            // $obj = new stdClass;
            // $obj->respDesc = Psr7\str($e->getRequest());
            // return json_encode($obj);
            return $e->getMessage();
        }
    }

    protected static function PostRequestMam($endpoint, $header = null, $body)
    {

        try {
            if ($header == null) {
                $client = new Client([
                    'headers' => [
                        // 'Content-Type' => 'application/json',
                        'Content-Type' => 'application/x-www-form-urlencoded',
                    ],
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            } else {
                $client = new Client([
                    'headers' => $header,
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            }

            $response = $client->post(
                $endpoint,
                [
                    'form_params' => $body,
                    'timeout' => env('REQUEST_TIMEOUT_IN_SECONDS', 3000),
                ]
            );

            return $response->getBody()->getContents();
        } catch (RequestException $e) {
            // $obj = new stdClass;
            // $obj->respDesc = Psr7\str($e->getRequest());
            // return json_encode($obj);
            if ($e->hasResponse()) {
                $obj = new stdClass;
                $exception = (string) $e->getResponse()->getBody();
                $exception = json_decode($exception);
                $obj->statusCode = $e->getCode();
                $obj->respDesc = $exception;
                return json_encode($obj);
            } else {
                $obj = new stdClass;
                $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
                // "Connection Error. Check VPN and Etc.." ;
                return json_encode($obj);
            }
        }
    }
    protected static function GetRequestMam($endpoint, $header = null, $body)
    {

        try {
            if ($header == null) {
                $client = new Client([
                    'headers' => [
                        // 'Content-Type' => 'application/json',
                        'Content-Type' => 'application/x-www-form-urlencoded',
                    ],
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            } else {
                $client = new Client([
                    'headers' => $header,
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            }

            $response = $client->get(
                $endpoint,
                [
                    'form_params' => $body,
                    'timeout' => env('REQUEST_TIMEOUT_IN_SECONDS', 3000),
                ]
            );

            return $response->getBody()->getContents();
        } catch (RequestException $e) {
            // $obj = new stdClass;
            // $obj->respDesc = Psr7\str($e->getRequest());
            // return json_encode($obj);
            if ($e->hasResponse()) {
                $obj = new stdClass;
                $exception = (string) $e->getResponse()->getBody();
                $exception = json_decode($exception);
                $obj->statusCode = $e->getCode();
                $obj->respDesc = $exception;
                return json_encode($obj);
            } else {
                $obj = new stdClass;
                $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
                // "Connection Error. Check VPN and Etc.." ;
                return json_encode($obj);
            }
        }
    }

    protected static function PostRequestMamJsonBody($endpoint, $header = null, $body)
    {

        try {
            if ($header == null) {
                $client = new Client([
                    'headers' => [
                        'Content-Type' => 'application/json',
                        // 'Content-Type' => 'application/x-www-form-urlencoded',
                    ],
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            } else {
                $client = new Client([
                    'headers' => $header,
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            }

            $response = $client->post(
                $endpoint,
                [
                    'json' => $body,
                    'timeout' => env('REQUEST_TIMEOUT_IN_SECONDS', 3000),
                ]
            );

            return $response->getBody()->getContents();
        } catch (RequestException $e) {
            // $obj = new stdClass;
            // $obj->respDesc = Psr7\str($e->getRequest());
            // return json_encode($obj);
            if ($e->hasResponse()) {
                $obj = new stdClass;
                $exception = (string) $e->getResponse()->getBody();
                $exception = json_decode($exception);
                $obj->statusCode = $e->getCode();
                $obj->respDesc = $exception;
                return json_encode($obj);
            } else {
                $obj = new stdClass;
                $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
                // "Connection Error. Check VPN and Etc.." ;
                return json_encode($obj);
            }
        }
    }
    protected static function DeleteRequestMamJsonBody($endpoint, $header = null, $body)
    {

        try {
            if ($header == null) {
                $client = new Client([
                    'headers' => [
                        'Content-Type' => 'application/json',
                        // 'Content-Type' => 'application/x-www-form-urlencoded',
                    ],
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            } else {
                $client = new Client([
                    'headers' => $header,
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            }

            $response = $client->delete(
                $endpoint,
                [
                    'json' => $body,
                    'timeout' => env('REQUEST_TIMEOUT_IN_SECONDS', 3000),
                ]
            );

            return $response->getBody()->getContents();
        } catch (RequestException $e) {
            // $obj = new stdClass;
            // $obj->respDesc = Psr7\str($e->getRequest());
            // return json_encode($obj);
            if ($e->hasResponse()) {
                $obj = new stdClass;
                $exception = (string) $e->getResponse()->getBody();
                $exception = json_decode($exception);
                $obj->statusCode = $e->getCode();
                $obj->respDesc = $exception;
                return json_encode($obj);
            } else {
                $obj = new stdClass;
                $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
                // "Connection Error. Check VPN and Etc.." ;
                return json_encode($obj);
            }
        }
    }

    protected static function PutRequestMamJsonBody($endpoint, $header = null, $body)
    {

        try {
            if ($header == null) {
                $client = new Client([
                    'headers' => [
                        'Content-Type' => 'application/json',
                        // 'Content-Type' => 'application/x-www-form-urlencoded',
                    ],
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            } else {
                $client = new Client([
                    'headers' => $header,
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            }

            $response = $client->put(
                $endpoint,
                [
                    'json' => $body,
                    'timeout' => env('REQUEST_TIMEOUT_IN_SECONDS', 3000),
                ]
            );

            return $response->getBody()->getContents();
        } catch (RequestException $e) {
            // $obj = new stdClass;
            // $obj->respDesc = Psr7\str($e->getRequest());
            // return json_encode($obj);
            if ($e->hasResponse()) {
                $obj = new stdClass;
                $exception = (string) $e->getResponse()->getBody();
                $exception = json_decode($exception);
                $obj->statusCode = $e->getCode();
                $obj->respDesc = $exception;
                return json_encode($obj);
            } else {
                $obj = new stdClass;
                $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
                // "Connection Error. Check VPN and Etc.." ;
                return json_encode($obj);
            }
        }
    }

    protected static function PostRequestMamMultipart($endpoint, $header = null, $body, $fileParameterName)
    {
        try {
            if ($header == null) {
                $client = new Client([
                    'headers' => [
                        'Content-Type' => 'application/json',
                    ],
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            } else {
                $client = new Client([
                    'headers' => $header,
                    'verify' => env('SSL_VERIFICATION', false)
                ]);
            }

            // Check if body contains a file parameter
            $hasFile = false;
            foreach ($body as $key => $value) {
                if ($value instanceof \Illuminate\Http\UploadedFile) {
                    $hasFile = true;
                    break;
                }
            }

            $multipartBody = [];
            $multipartBody[] = [
                'name' => "file",
                'contents' => fopen($body->{$fileParameterName}->path(), 'r'),
                'filename' => $body->{$fileParameterName}->getClientOriginalName()
            ];
            // dd($multipartBody);
            // foreach ($body as $key => $value) {
            //     if ($value instanceof \Illuminate\Http\UploadedFile) {
            //         $multipartBody[] = [
            //             'name' => "file",
            //             'contents' => fopen($value->path(), 'r'),
            //             'filename' => $value->getClientOriginalName()
            //         ];
            //     } else {
            //         $multipartBody[] = [
            //             'name' => $key,
            //             'contents' => $value
            //         ];
            //     }
            // }

            $response = $client->post(
                $endpoint,
                [
                    'multipart' => $multipartBody,
                    'timeout' => 300,
                ]
            );

            return $response->getBody()->getContents();
        } catch (RequestException $e) {
            if ($e->hasResponse()) {
                $obj = new stdClass;
                $exception = (string) $e->getResponse()->getBody();
                $exception = json_decode($exception);
                $obj->statusCode = $e->getCode();
                $obj->respDesc = $exception;
                return json_encode($obj);
            } else {
                $obj = new stdClass;
                $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
                return json_encode($obj);
            }
        }
    }

    protected static function PostRequestLeanx($endpoint, $header = null, $body)
    {

        try {
            if ($header == null) {
                $client = new Client([
                    'headers' => [
                        'Content-Type' => 'application/json',
                        // 'Content-Type' => 'application/x-www-form-urlencoded',
                    ],
                ]);
            } else {
                $client = new Client([
                    'headers' => $header,
                ]);
            }

            $response = $client->post(
                $endpoint,
                [
                    // 'form_params' => $body,
                    'json' => $body,
                    'timeout' => env('REQUEST_TIMEOUT_IN_SECONDS', 3000),
                ]
            );

            return $response->getBody()->getContents();
        } catch (RequestException $e) {
            // $obj = new stdClass;
            // $obj->respDesc = Psr7\str($e->getRequest());
            // return json_encode($obj);
            if ($e->hasResponse()) {
                $obj = new stdClass;
                $exception = (string) $e->getResponse()->getBody();
                $exception = json_decode($exception);
                $obj->statusCode = $e->getCode();
                $obj->respDesc = $exception;
                $obj->response_code = 10000;
                return json_encode($obj);
            } else {
                $obj = new stdClass;
                $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
                $obj->response_code = 10000;
                // "Connection Error. Check VPN and Etc.." ;
                return json_encode($obj);
            }
        } catch (\GuzzleHttp\Exception\ConnectException $e) {
            $obj = new stdClass;
            $obj->respDesc = $e->getMessage() != null ? $e->getMessage() : "Connection Error. Check VPN and Etc..";
            $obj->response_code = 10000;
            // "Connection Error. Check VPN and Etc.." ;
            return json_encode($obj);
        }
    }

    protected static function GenerateSignature($UUID, $AUTH_TOKEN, $HASH_KEY, $HTTP_METHOD, $URL_PATH)
    {
        // Replace placeholders with actual values
        $PLATFORM = "api";
        $API_VERSION = "v1";

        // Replace placeholders in the URL path
        $URL_PATH = str_replace("{{PLATFORM}}", $PLATFORM, $URL_PATH);
        $URL_PATH = str_replace("{{API_VERSION}}", $API_VERSION, $URL_PATH);

        // Get the current timestamp in seconds
        $TIME_STAMP = time();

        // Generate a random UUID for the nonce
        $NONCE = self::generateUuidV4();

        // Create the message to be hashed
        $message = "{$HTTP_METHOD}|{$UUID}|{$URL_PATH}|{$TIME_STAMP}|{$AUTH_TOKEN}|{$NONCE}";

        // Generate the HMAC signature using SHA256
        $hmacSignature = hash_hmac('sha256', $message, $HASH_KEY);

        // Return the headers
        return [
            'x-signature' => $hmacSignature,
            'x-timestamp' => $TIME_STAMP,
            'x-nonce' => $NONCE
        ];
    }

    protected static function GenerateJwtTokenForRequestSignature($HASH_KEY, $AUTH_TOKEN, $HTTP_METHOD, $URL_PATH)
    {
        $secretKey = $HASH_KEY;

        $iat = new DateTime();
        $exp = $iat->modify("+5 minutes");

        $payload = new stdClass;
        $payload->{"auth-token"} = $AUTH_TOKEN;
        $payload->{"http_method"} = $HTTP_METHOD;
        $payload->{"url_path"} = $URL_PATH;
        $payload->{"iat"} = $iat->getTimestamp();
        $payload->{"exp"} = $exp->getTimestamp();

        try {
            $encoded = JWT::encode(json_decode(json_encode($payload), true), $secretKey, 'HS256');
            return $encoded; // Convert the decoded object to an array
        } catch (ExpiredException $e) {
            // Handle expired token
            return ['error' => 'Token expired'];
        } catch (SignatureInvalidException $e) {
            // Handle invalid signature
            return ['error' => 'Invalid token signature'];
        } catch (\Exception $e) {
            // Handle other possible exceptions
            return ['error' => 'Invalid token: ' . $e->getMessage()];
        }
    }

    private static function generateUuidV4()
    {
        return sprintf(
            '%04x%04x-%04x-4%03x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff)
        );
    }
}
