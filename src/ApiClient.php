<?php

namespace GlpiPlugin\Sentinelone;

class ApiClient
{
   private string $baseUrl;
   private string $basePath;
   private string $authScheme;
   private string $token;
   private int $timeout;

   public function __construct(
      string $baseUrl,
      string $token,
      string $basePath = '/web/api/v2.1',
      string $authScheme = 'ApiToken',
      int $timeout = 30
   ) {
      $this->baseUrl = rtrim($baseUrl, '/');
      $this->basePath = '/' . trim($basePath, '/');
      $this->authScheme = trim($authScheme) ?: 'ApiToken';
      $this->token = $token;
      $this->timeout = max(5, min(120, $timeout));
   }

   public static function fromConfig(?array $config = null): self
   {
      $config ??= Config::getConfig();

      return new self(
         (string)$config['base_url'],
         (string)$config['api_token'],
         (string)$config['base_path'],
         (string)$config['auth_scheme'],
         (int)$config['timeout']
      );
   }

   public function testConnection(): array
   {
      return $this->request('GET', '/agents', ['limit' => 1]);
   }

   public function getAgents(array $params = [], int $maxPages = 10): array
   {
      return $this->collectPaginated('/agents', $params, $maxPages);
   }

   public function getThreats(array $params = [], int $maxPages = 10): array
   {
      return $this->collectPaginated('/threats', $params, $maxPages);
   }

   public function getThreatNotes(string $threatId): array
   {
      $response = $this->request('GET', '/threats/' . rawurlencode($threatId) . '/notes');
      $data = $response['data'] ?? [];
      return is_array($data) ? $data : [];
   }

   public function getActivities(array $params = [], int $maxPages = 3): array
   {
      return $this->collectPaginated('/activities', $params, $maxPages);
   }

   public function getAgentApplications(string $agentId): array
   {
      return $this->collectPaginated('/agents/' . rawurlencode($agentId) . '/applications', ['limit' => 200], 5);
   }

   public function getAgentCves(string $agentId): array
   {
      return $this->collectPaginated('/threats/cve', ['agentIds' => $agentId, 'limit' => 100], 10);
   }

   public function getRogueDevices(array $params = [], int $maxPages = 20): array
   {
      return $this->collectPaginated('/ranger/rogues/endpoints', array_merge(['limit' => 100], $params), $maxPages);
   }

   // ---- Threat actions ----

   public function mitigateThreat(string $threatId, string $action = 'kill_and_quarantine'): array
   {
      return $this->request('POST', '/threats/actions/mitigate', [], [
         'data'   => ['action' => $action],
         'filter' => ['ids' => [$threatId]],
      ]);
   }

   public function rollbackThreat(string $threatId): array
   {
      return $this->request('POST', '/threats/actions/rollback-remediation', [], [
         'data'   => (object)[],
         'filter' => ['ids' => [$threatId]],
      ]);
   }

   public function setThreatVerdict(string $threatId, string $verdict): array
   {
      return $this->request('POST', '/threats/analyst-verdict', [], [
         'data'   => ['analystVerdict' => $verdict],
         'filter' => ['ids' => [$threatId]],
      ]);
   }

   // ---- Agent remote actions ----

   public function scanAgent(string $sentineloneId): array
   {
      return $this->request('POST', '/agents/actions/initiateScan', [], [
         'data'   => (object)[],
         'filter' => ['ids' => [$sentineloneId]],
      ]);
   }

   public function updateAgent(string $sentineloneId): array
   {
      return $this->request('POST', '/agents/actions/update', [], [
         'data'   => ['packageType' => 'AgentAndRanger'],
         'filter' => ['ids' => [$sentineloneId]],
      ]);
   }

   public function restartAgent(string $sentineloneId): array
   {
      return $this->request('POST', '/agents/actions/restart-services', [], [
         'data'   => (object)[],
         'filter' => ['ids' => [$sentineloneId]],
      ]);
   }

   public function getGroups(array $params = [], int $maxPages = 5): array
   {
      return $this->collectPaginated('/groups', array_merge(['limit' => 100], $params), $maxPages);
   }

   public function getGroupPolicy(string $groupId): array
   {
      $response = $this->request('GET', '/policy', ['groupIds' => $groupId]);
      $data = $response['data'] ?? [];
      return is_array($data) ? $data : [];
   }

   public function quarantineAgent(string $sentineloneId): array
   {
      return $this->request('POST', '/agents/actions/disconnect', [], [
         'data'   => (object)[],
         'filter' => ['ids' => [$sentineloneId]],
      ]);
   }

   public function unquarantineAgent(string $sentineloneId): array
   {
      return $this->request('POST', '/agents/actions/connect', [], [
         'data'   => (object)[],
         'filter' => ['ids' => [$sentineloneId]],
      ]);
   }

   public function request(string $method, string $path, array $query = [], ?array $body = null): array
   {
      $url = $this->buildUrl($path, $query);
      $headers = [
         'Accept: application/json',
         'Content-Type: application/json',
         'Authorization: ' . $this->authScheme . ' ' . $this->token,
      ];

      if (function_exists('curl_init')) {
         return $this->requestWithCurl($method, $url, $headers, $body);
      }

      return $this->requestWithStreams($method, $url, $headers, $body);
   }

   private function collectPaginated(string $path, array $params, int $maxPages): array
   {
      $items = [];
      $cursor = null;
      $maxPages = max(1, $maxPages);

      for ($page = 0; $page < $maxPages; $page++) {
         if ($cursor !== null) {
            $params['cursor'] = $cursor;
         }

         $response = $this->request('GET', $path, $params);
         $items = array_merge($items, $this->extractItems($response));
         $cursor = $response['pagination']['nextCursor']
            ?? $response['pagination']['next_cursor']
            ?? $response['nextCursor']
            ?? null;

         if ($cursor === null || $cursor === '') {
            break;
         }
      }

      return $items;
   }

   private function extractItems(array $response): array
   {
      $data = $response['data'] ?? [];

      if (!is_array($data)) {
         return [];
      }

      if ($data === [] || array_is_list($data)) {
         return $data;
      }

      foreach ($data as $value) {
         if (is_array($value) && array_is_list($value)) {
            return $value;
         }
      }

      return [$data];
   }

   private function requestWithCurl(string $method, string $url, array $headers, ?array $body): array
   {
      $curl = curl_init($url);
      curl_setopt_array($curl, [
         CURLOPT_CUSTOMREQUEST  => strtoupper($method),
         CURLOPT_HTTPHEADER     => $headers,
         CURLOPT_RETURNTRANSFER => true,
         CURLOPT_TIMEOUT        => $this->timeout,
         CURLOPT_SSL_VERIFYPEER => true,
         CURLOPT_SSL_VERIFYHOST => 2,
      ]);

      if ($body !== null) {
         curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_SLASHES));
      }

      $raw = curl_exec($curl);
      $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
      $error = curl_error($curl);
      curl_close($curl);

      if ($raw === false) {
         throw new \RuntimeException('Falha HTTP SentinelOne: ' . $error);
      }

      return $this->decodeResponse((string)$raw, $status);
   }

   private function requestWithStreams(string $method, string $url, array $headers, ?array $body): array
   {
      $context = stream_context_create([
         'http' => [
            'method'        => strtoupper($method),
            'header'        => implode("\r\n", $headers),
            'content'       => $body !== null ? json_encode($body, JSON_UNESCAPED_SLASHES) : '',
            'timeout'       => $this->timeout,
            'ignore_errors' => true,
         ],
      ]);

      $raw = @file_get_contents($url, false, $context);
      $status = 0;

      foreach ($http_response_header ?? [] as $header) {
         if (preg_match('/^HTTP\/\S+\s+(\d+)/', $header, $matches)) {
            $status = (int)$matches[1];
            break;
         }
      }

      if ($raw === false) {
         throw new \RuntimeException('Falha HTTP SentinelOne usando stream wrapper.');
      }

      return $this->decodeResponse((string)$raw, $status);
   }

   private function decodeResponse(string $raw, int $status): array
   {
      $json = json_decode($raw, true);

      if (!is_array($json)) {
         throw new \RuntimeException('Resposta SentinelOne nao e JSON valido.');
      }

      if ($status >= 400) {
         $message = $json['errors'][0]['detail']
            ?? $json['error']
            ?? $json['message']
            ?? 'Erro HTTP ' . $status;
         throw new \RuntimeException('Erro SentinelOne: ' . $message);
      }

      $json['_http_status'] = $status;

      return $json;
   }

   private function buildUrl(string $path, array $query): string
   {
      $url = $this->baseUrl . $this->basePath . '/' . ltrim($path, '/');

      if ($query !== []) {
         $url .= '?' . http_build_query($query);
      }

      return $url;
   }
}
