<?php

declare(strict_types=1);

namespace Torxy\Core;

use OverflowException;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;
use React\Stream\ReadableStreamInterface;
use RuntimeException;
use Throwable;

/**
 * Decides how a client's request body travels upstream, and collects it when it can.
 *
 * A streamed body is consumed by the first upstream attempt: the bytes are gone by the time
 * it fails, so the request cannot be replayed on another circuit. Retrying is what makes
 * flaky Tor exits tolerable, so a body small enough to hold is buffered to keep that option
 * open, and only a body that would be reckless to hold is streamed at the cost of a single
 * attempt.
 */
final class RequestBodyReader
{
    /**
     * Largest body held in memory so the request stays replayable. Covers ordinary form
     * posts and API calls. Past this, holding the body costs more than a retry is worth —
     * several concurrent uploads would have to fit alongside each other in the same
     * memory_limit.
     */
    public const MAX_REPLAYABLE_BYTES = 1048576;

    /**
     * Whether a body of this size can be held in memory, and therefore retried.
     *
     * @param int|null $size Body length in bytes, or null when the client sent
     *                       `Transfer-Encoding: chunked` and the length is not known yet.
     */
    public static function isReplayable(?int $size): bool
    {
        // An unknown length cannot be bounded before reading it, and a chunked upload is
        // exactly the shape that may turn out to be arbitrarily large.
        if ($size === null) {
            return false;
        }

        return $size <= self::MAX_REPLAYABLE_BYTES;
    }

    /**
     * Collect a readable stream into a string.
     *
     * react/promise-stream is not a dependency, so this is hand-rolled the same way
     * TorController's async control session is.
     *
     * @return PromiseInterface<string> Rejects with OverflowException if the stream delivers
     *                                  more than $limit bytes.
     */
    public static function buffer(ReadableStreamInterface $stream, int $limit): PromiseInterface
    {
        $deferred = new Deferred(static function () use ($stream): void {
            $stream->close();
        });

        $buffer = '';

        // Every listener below races the others, and a settled Deferred ignores further
        // calls — but the buffer must still stop growing once one of them has won.
        $settled = false;

        $stream->on('data', function ($chunk) use (&$buffer, &$settled, $limit, $deferred, $stream): void {
            if ($settled) {
                return;
            }

            $buffer .= (string) $chunk;

            if (strlen($buffer) <= $limit) {
                return;
            }

            // Reject rather than truncate. Forwarding a short body under the client's own
            // Content-Length is the silent data loss this class exists to prevent.
            $settled = true;
            $buffer = '';

            $deferred->reject(new OverflowException(
                "Request body exceeds the {$limit} byte buffer limit"
            ));

            $stream->close();
        });

        $stream->on('end', function () use (&$buffer, &$settled, $deferred): void {
            if ($settled) {
                return;
            }

            $settled = true;
            $deferred->resolve($buffer);
        });

        $stream->on('error', function (Throwable $e) use (&$settled, $deferred): void {
            if ($settled) {
                return;
            }

            $settled = true;
            $deferred->reject($e);
        });

        // `close` without a preceding `end` means the client went away mid-upload. Left
        // unhandled the promise would never settle and the request would hang.
        $stream->on('close', function () use (&$settled, $deferred): void {
            if ($settled) {
                return;
            }

            $settled = true;
            $deferred->reject(new RuntimeException('Request body closed before it ended'));
        });

        return $deferred->promise();
    }
}
