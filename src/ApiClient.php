<?php

namespace GlpiPlugin\Sentinelone;

class ApiClient
{
   private string $baseUrl;
   private string $basePath;
   private string $authScheme;
   private string $token;
   private int $timeout;
   private int $maxRetries;

   public function __construct(
      string $baseUrl,
      string $token,
      string $basePath = '/web/api/v2.1',
      string $authScheme = 'ApiToken',
      int $timeout = 30,
      int $maxRetries = 3
   ) {
      $this->baseUrl = rtrim($baseUrl, '/');
      $this->basePath = '/' . trim($basePath, '/');
      $this->authScheme = trim($authScheme) ?: 'ApiToken';
      $this->token = $token;
      $this->timeout = max(5, min(120, $timeout));
      $this->maxRetries = max(0, min(5, $maxRetries));
   }

   /**
    * Cliente "fail-fast" para sondagens (ex.: verificacao de permissoes): timeout
    * curto e sem retry, para nao travar a UI quando um modulo demora ou erra.
    */
   public static function probe(?array $config = null): self
   {
      $config ??= Config::getConfig();

      return new self(
         (string)$config['base_url'],
         (string)$config['api_token'],
         (string)$config['base_path'],
         (string)$config['auth_scheme'],
         8,
         0
      );
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

   /**
    * CVEs affecting one agent, resolved through its risky installed applications.
    *
    * SentinelOne has no agent->CVE endpoint, so the chain is:
    *   1. list the agent's applications carrying risk (riskLevelsNin=none)
    *   2. fetch the CVEs of each of those applications
    * Each returned CVE is enriched with the originating application name/version,
    * since the /installed-applications/cves payload does not carry it.
    *
    * @param string $agentUuid SentinelOne agent UUID (column `uuid`), not the agent id.
    */
   public function getAgentCves(string $agentUuid): array
   {
      $agentUuid = trim($agentUuid);
      if ($agentUuid === '') {
         return [];
      }

      $apps = $this->collectPaginated('/installed-applications', [
         'agentUuid__contains' => $agentUuid,
         'riskLevelsNin'       => 'none',
         'limit'               => 100,
      ], 5);

      $cves = [];
      foreach ($apps as $app) {
         // Guard against the "contains" filter matching a different agent.
         if (isset($app['agentUuid']) && strcasecmp((string)$app['agentUuid'], $agentUuid) !== 0) {
            continue;
         }

         $appId = trim((string)($app['id'] ?? ''));
         if ($appId === '') {
            continue;
         }

         foreach ($this->getApplicationCves($appId) as $cve) {
            $cve['application_name']    = $app['name'] ?? null;
            $cve['application_version'] = $app['version'] ?? null;
            $cves[] = $cve;
         }
      }

      return $cves;
   }

   /**
    * Every installed application carrying risk across the whole account
    * (riskLevel != none). Used to resolve CVEs for the entire fleet in a single
    * pass instead of one request per agent. Each item carries `agentUuid`,
    * `agentComputerName`, `id`, `name`, `version` and `riskLevel`.
    */
   public function getRiskyApplications(array $params = [], int $maxPages = 30): array
   {
      return $this->collectPaginated('/installed-applications', array_merge([
         'riskLevelsNin' => 'none',
         'limit'         => 100,
      ], $params), $maxPages);
   }

   /**
    * CVEs of a single installed application (by SentinelOne application id).
    */
   public function getApplicationCves(string $applicationId, int $maxPages = 5): array
   {
      $applicationId = trim($applicationId);
      if ($applicationId === '') {
         return [];
      }

      return $this->collectPaginated('/installed-applications/cves', [
         'applicationIds' => $applicationId,
         'limit'          => 100,
      ], $maxPages);
   }

   public function getRogueDevices(array $params = [], int $maxPages = 20): array
   {
      // SentinelOne "Unprotected Endpoints Discovery" (rogues) table.
      // See swagger: GET /web/api/v2.1/rogues/table-view
      return $this->collectPaginated('/rogues/table-view', array_merge(['limit' => 100], $params), $maxPages);
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

      $maxRetries = $this->maxRetries;
      $delay      = 1;
      $last       = null;

      for ($attempt = 0; $attempt <= $maxRetries; $attempt++) {
         if ($attempt > 0) {
            sleep($delay);
            $delay = min($delay * 2, 16);
         }

         try {
            return function_exists('curl_init')
               ? $this->requestWithCurl($method, $url, $headers, $body)
               : $this->requestWithStreams($method, $url, $headers, $body);
         } catch (\RuntimeException $e) {
            if (!self::isRetryableError($e->getMessage())) {
               throw $e;
            }
            $last = $e;
            if (str_contains($e->getMessage(), '429')) {
               $delay = max($delay, 10);
            }
         }
      }

      throw $last;
   }

   private static function isRetryableError(string $message): bool
   {
      return str_contains($message, '429')
         || str_contains($message, 'HTTP 500')
         || str_contains($message, 'HTTP 502')
         || str_contains($message, 'HTTP 503')
         || str_contains($message, 'HTTP 504')
         || str_contains($message, 'Falha HTTP SentinelOne');
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
         foreach ($this->extractItems($response) as $item) {
            $items[] = $item;
         }
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
         CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_2TLS,
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

      // Checa o status HTTP antes de tentar interpretar o corpo, para que erros
      // 4xx/5xx com resposta HTML (ex.: pagina de manutencao, rate-limit) gerem
      // mensagens uteis em vez de "nao e JSON valido".
      if ($status >= 400) {
         $message = is_array($json)
            ? ($json['errors'][0]['detail'] ?? $json['error'] ?? $json['message'] ?? 'Erro HTTP ' . $status)
            : 'Erro HTTP ' . $status . self::rawPreview($raw);
         throw new \RuntimeException('Erro SentinelOne: ' . $message);
      }

      if (!is_array($json)) {
         throw new \RuntimeException(
            'Resposta SentinelOne nao e JSON valido'
            . ($status > 0 ? ' (HTTP ' . $status . ')' : '')
            . self::rawPreview($raw)
         );
      }

      $json['_http_status'] = $status;

      return $json;
   }

   /**
    * Retorna um trecho legivel da resposta bruta para incluir nas mensagens de erro.
    * Remove tags HTML e limita a 160 chars para nao entupir os logs.
    */
   private static function rawPreview(string $raw): string
   {
      $preview = trim(strip_tags($raw));
      $preview = preg_replace('/\s+/', ' ', $preview) ?? $preview;
      $preview = mb_substr($preview, 0, 160);

      return $preview !== '' ? '. Resposta: ' . $preview : '';
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
