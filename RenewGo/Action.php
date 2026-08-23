<?php
declare(strict_types=1);

namespace TypechoPlugin\RenewGo;

use Typecho\Widget;
use Widget\User;
use Widget\Security;
use Utils\Helper;
use Typecho\Cache;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Action extends Widget
{
    private const MAX_JSON_SIZE = 32768;
    private const CLEANUP_INTERVAL = 3600;
    private const CLEANUP_LOCK_TTL = 60;

    public function action()
    {
        $do = (string) $this->request->get('do');

        if ($do === 'jump') {
            $this->jump();
            return;
        }

        $this->guardAdmin();

        switch ($do) {
            case 'test':
                $this->requirePost();
                $this->testRule();
                return;
            case 'purge':
                $this->requirePost();
                $this->purgeLogs();
                return;
            case 'export':
                $this->requirePost();
                $this->exportRules();
                return;
            case 'import':
                $this->requirePost();
                $this->importRules();
                return;
            default:
                $this->jsonError(_t('无效操作'), 400, 'invalid_action');
        }
    }

    public function go()
    {
        $settings = Plugin::getSettings();
        $keepDays = (int) ($settings['logKeepDays'] ?? 0);
        if ($keepDays > 0) {
            $this->maybeCleanupLogs($keepDays);
        }
        if ((string) ($settings['enabled'] ?? '1') !== '1') {
            $this->failPage('go', 'disabled', '', _t('外链跳转功能已停用'), 403, true);
            return;
        }
        $encoded = trim((string) $this->request->get('target', ''));
        ['decoded' => $decoded, 'url' => $url] = $this->resolveTarget($encoded);

        if ($url === '') {
            $this->failPage('go', 'invalid', $decoded, _t('链接无效或已损坏'));
            return;
        }

        if ($settings['mode'] === 'off') {
            $this->failPage('go', 'disabled', $url, _t('外链跳转功能已关闭'));
            return;
        }

        if ($settings['mode'] === 'direct302') {
            $isWhitelisted = Plugin::isWhitelisted($url, $settings);
            $whitelistOnly = (string) ($settings['directWhitelistOnly'] ?? '1') === '1';
            if ($whitelistOnly) {
                $whitelist = trim((string) ($settings['whitelist'] ?? ''));
                if ($whitelist === '') {
                    $this->failPage('go', 'no-whitelist', $url, _t('直跳模式未配置白名单，请联系管理员'), 200, true);
                    return;
                }
                if (!$isWhitelisted) {
                    $this->failPage('go', 'direct-denied', $url, _t('该外链未在直跳白名单中'), 200, true);
                    return;
                }
            }
            if (!$this->enforceRateLimit($settings, 'go', 'redirect', $url)) {
                return;
            }
            $this->response->redirect($url);
            return;
        }

        $jumpUrl = Plugin::buildJumpUrl($encoded);
        $title = (string) ($settings['pageTitle'] ?? _t('外链访问提示'));
        $staySeconds = (int) ($settings['staySeconds'] ?? 0);
        $host = (string) parse_url($url, PHP_URL_HOST);
        $display = Plugin::textCut($url, 120) !== $url ? Plugin::textCut($url, 117) . '...' : $url;
        $home = $this->siteUrl();
        $newTab = (string) ($settings['openInNewTab'] ?? '1') === '1';
        $template = __DIR__ . '/view/interstitial.php';

        Plugin::logEvent('go', 'interstitial', $url, (string) $this->request->getReferer(), true);

        if (file_exists($template)) {
            include $template;
            return;
        }

        $this->response->redirect($url);
    }

    private function jump(): void
    {
        $settings = Plugin::getSettings();
        $keepDays = (int) ($settings['logKeepDays'] ?? 0);
        if ($keepDays > 0) {
            $this->maybeCleanupLogs($keepDays);
        }

        if ((string) ($settings['enabled'] ?? '1') !== '1') {
            $this->failPage('jump', 'disabled', '', _t('外链跳转功能已停用'), 403, true);
            return;
        }

        if (($settings['mode'] ?? '') === 'off') {
            $this->failPage('jump', 'disabled', '', _t('外链跳转功能已关闭'), 403, true);
            return;
        }

        $encoded = trim((string) $this->request->get('target', ''));
        $time = (int) $this->request->get('ts');
        $sign = (string) $this->request->get('sig');
        if (!Plugin::verifySign($encoded, $time, $sign)) {
            $this->failPage('jump', 'forbidden', '', _t('链接校验失败'), 403, true);
            return;
        }

        ['decoded' => $decoded, 'url' => $url] = $this->resolveTarget($encoded);
        if ($url === '') {
            $this->failPage('jump', 'invalid', $decoded, _t('链接无效或已损坏'), 200, true);
            return;
        }

        if (!$this->enforceRateLimit($settings, 'jump', 'success', $url)) {
            return;
        }

        $this->response->redirect($url);
    }

    private function testRule(): void
    {
        $raw = $this->rawJson();
        $url = Plugin::normalizeUrl((string) ($raw['url'] ?? ''));
        if ($url === '') {
            $this->jsonError(_t('URL 格式无效'), 400, 'invalid_url');
        }

        $settings = Plugin::getSettings();
        $whitelisted = Plugin::isWhitelisted($url, $settings);
        $rewrite = Plugin::shouldRewriteUrl($url, $settings);
        $this->jsonSuccess([
            'success' => 1,
            'url' => $url,
            'whitelisted' => $whitelisted ? 1 : 0,
            'rewrite' => $rewrite ? 1 : 0,
            'go' => $rewrite ? Plugin::buildGoUrl($url) : $url
        ]);
    }

    private function purgeLogs(): void
    {
        Plugin::purgeLogs();
        $this->jsonSuccess(['success' => 1]);
    }

    private function exportRules(): void
    {
        $data = Plugin::exportRules();
        $this->jsonSuccess(['success' => 1, 'data' => $data]);
    }

    private function importRules(): void
    {
        $raw = $this->rawJson();
        $rules = (string) ($raw['rules'] ?? '');
        $settings = Plugin::importRules($rules);
        $this->jsonSuccess(['success' => 1, 'whitelist' => $settings['whitelist'] ?? '']);
    }

    private function rawJson(): array
    {
        $body = $this->request->getRawBody();
        if (strlen($body) > self::MAX_JSON_SIZE) {
            $this->jsonError(_t('请求体过大'), 413, 'payload_too_large');
        }
        if (trim($body) === '') {
            return [];
        }
        try {
            $json = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->jsonError(_t('请求 JSON 无效'), 400, 'invalid_json');
        }
        return is_array($json) ? $json : [];
    }

    private function requirePost(): void
    {
        if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
            $this->jsonError(_t('请求方法不被允许'), 405, 'method_not_allowed');
        }
    }

    private function guardAdmin(): void
    {
        User::alloc()->pass('administrator');
        $token = (string) $this->request->get('_');
        $expect = Security::alloc()->getToken('renew-go-admin');
        if (!hash_equals($expect, $token)) {
            $this->jsonError(_t('请求校验失败'), 403, 'forbidden');
        }
    }

    private function renderError(string $message): void
    {
        $settings = Plugin::getSettings();
        $title = (string) ($settings['pageTitle'] ?? _t('外链访问提示'));
        $host = '';
        $display = $message;
        $home = $this->siteUrl();
        $jumpUrl = $home;
        $staySeconds = 0;
        $newTab = false;
        include __DIR__ . '/view/interstitial.php';
    }

    private function siteUrl(): string
    {
        $site = (string) Helper::options()->siteUrl;
        if ($site === '') {
            $site = (string) $this->request->getUrlPrefix();
        }

        return rtrim($site !== '' ? $site : '/', '/') . '/';
    }

    private function resolveTarget(string $encoded): array
    {
        $decoded = Plugin::decodeTarget($encoded);

        return [
            'decoded' => $decoded,
            'url' => Plugin::normalizeUrl($decoded)
        ];
    }

    private function enforceRateLimit(array $settings, string $scope, string $result, string $url): bool
    {
        $ip = (string) $this->request->getIp();
        if (!Plugin::checkRateLimit($ip, $settings)) {
            $this->failPage($scope, 'rate-limit', $url, _t('访问过于频繁，请稍后重试'), 429, true);
            return false;
        }

        if (!Plugin::logEvent(
            $scope,
            $result,
            $url,
            (string) $this->request->getReferer(),
            true
        )) {
            $this->response->setStatus(503);
            $this->renderError(_t('外链安全状态后端暂时不可用，请稍后重试'));
            return false;
        }

        return true;
    }

    private function failPage(
        string $scope,
        string $result,
        string $target,
        string $message,
        int $status = 200,
        bool $force = false
    ): void {
        Plugin::logEvent($scope, $result, $target, (string) $this->request->getReferer(), $force);
        if ($status !== 200) {
            $this->response->setStatus($status);
        }
        $this->renderError($message);
    }

    private function jsonError(string $message, int $status, string $code): void
    {
        $this->response->setStatus($status);
        $this->response->throwJson([
            'success' => 0,
            'error' => $message,
            'code' => $code
        ]);
    }

    private function jsonSuccess(array $data): void
    {
        if (!isset($data['success'])) {
            $data['success'] = 1;
        }
        $this->response->throwJson($data);
    }

    private function maybeCleanupLogs(int $keepDays): void
    {
        $cache = Cache::getInstance();
        $cacheKey = 'renewgo:last_cleanup';
        $lockKey = 'renewgo:cleanup_lock';
        $now = time();
        $interval = self::CLEANUP_INTERVAL;
        $locked = false;

        if ($cache->enabled()) {
            $hit = false;
            $lastCleanup = (int) $cache->get($cacheKey, $hit);
            if ($hit && ($now - $lastCleanup) < $interval) {
                return;
            }

            if (!$cache->tryLock($lockKey, self::CLEANUP_LOCK_TTL)) {
                return;
            }
            $locked = true;
        }

        try {
            Plugin::cleanupLogs($keepDays);
            if ($cache->enabled()) {
                $cache->set($cacheKey, $now, $interval * 2);
            }
        } catch (\Throwable $e) {
            error_log('RenewGo.cleanupLogs: ' . $e->getMessage());
        } finally {
            if ($cache->enabled() && $locked) {
                $cache->unlock($lockKey);
            }
        }
    }
}
