<?php

namespace dokuwiki\plugin\statistics;

/**
 * Turns one LOGGER_DATA_FORMAT event into a structured audit row
 *
 * Pure: no globals, no database. The request context (user, ip) is passed in.
 *
 * Extraction is convention based. All known sources write the message as
 * "<user> <action> ..." and pass a compact JSON object as details, carrying
 * user/ip/action (structured event plugins) or id/act/ip/user (logged plugin).
 * Unknown shapes still produce a row from facility, message and request context.
 */
class AuditRecord
{
    public const MAX_MESSAGE = 1000;
    public const MAX_DETAILS = 8000;

    /** detail values that mean "no user known" */
    protected const UNKNOWN_USERS = ['-', 'anonymous'];

    /** detail keys tried, in order, for the subject column unless configured otherwise */
    public const DEFAULT_SUBJECT_KEYS = ['id', 'page'];

    /**
     * @param array $data LOGGER_DATA_FORMAT event data: facility, datetime, message, details, file, line
     * @param array $request optional 'user' (REMOTE_USER) and 'ip' (client IP) of the current request
     * @param string[]|null $subjectKeys detail keys tried in order for the subject, null for the defaults
     * @return array row for AuditLog::store()
     */
    public static function fromLogEvent(array $data, array $request = [], ?array $subjectKeys = null): array
    {
        $message = self::oneLine((string)($data['message'] ?? ''));
        [$fields, $detailsText] = self::parseDetails($data['details'] ?? null);

        $rawUser = self::scalar($fields['user'] ?? null);
        $user = $rawUser;
        if ($user === '' || in_array($user, self::UNKNOWN_USERS, true)) {
            $user = self::scalar($request['user'] ?? null);
        }

        $ip = self::scalar($fields['ip'] ?? null);
        if ($ip === '') {
            $ip = self::scalar($request['ip'] ?? null);
        }

        $action = self::scalar($fields['action'] ?? $fields['act'] ?? null);
        if ($action === '') {
            $action = self::actionFromMessage($message, [$rawUser, $user]);
        }

        $subject = '';
        foreach ($subjectKeys ?? self::DEFAULT_SUBJECT_KEYS as $key) {
            $candidate = self::scalar($fields[$key] ?? null);
            if ($candidate !== '') {
                $subject = $candidate;
                break;
            }
        }

        return [
            'dt' => (int)($data['datetime'] ?? time()),
            'facility' => (string)($data['facility'] ?? ''),
            'user' => $user,
            'ip' => $ip,
            'action' => $action,
            'subject' => $subject,
            'message' => self::cap($message, self::MAX_MESSAGE),
            'details' => self::cap($detailsText, self::MAX_DETAILS),
            'file' => (string)($data['file'] ?? ''),
            'line' => (int)($data['line'] ?? 0),
        ];
    }

    /**
     * Split details into parsed fields and the text to store
     *
     * @param mixed $details
     * @return array{0: array, 1: string} [fields, text]
     */
    protected static function parseDetails($details): array
    {
        if ($details === null || $details === '' || $details === []) {
            return [[], ''];
        }

        if (is_array($details)) {
            return [$details, self::encode($details)];
        }

        if (is_string($details)) {
            $decoded = json_decode($details, true);
            if (is_array($decoded)) {
                return [$decoded, self::encode($decoded)];
            }
            return [[], $details];
        }

        return [[], (string)$details];
    }

    /**
     * Second token of the message when the first token names the user
     *
     * @param string $message
     * @param string[] $users accepted first tokens (raw detail value and resolved user)
     */
    protected static function actionFromMessage(string $message, array $users): string
    {
        $tokens = preg_split('/\s+/', trim($message));
        if (count($tokens) < 2) return '';

        $users = array_filter($users, static fn($u) => $u !== '');
        if (!in_array($tokens[0], $users, true)) return '';

        return $tokens[1];
    }

    protected static function encode(array $data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        return $json === false ? '' : $json;
    }

    protected static function oneLine(string $text): string
    {
        return trim(preg_replace('/[\r\n]+/', ' ', $text));
    }

    protected static function cap(string $text, int $max): string
    {
        if (strlen($text) <= $max) return $text;
        return substr($text, 0, $max - 3) . '...';
    }

    /**
     * A scalar detail value as string, '' for anything else
     *
     * @param mixed $value
     */
    protected static function scalar($value): string
    {
        return is_scalar($value) ? (string)$value : '';
    }
}
