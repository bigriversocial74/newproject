<?php

declare(strict_types=1);

namespace Vp3\Provisioning;

final class ProtectedConfigurationMerger
{
    /**
     * @param array<string,mixed> $existing
     * @param array<string,mixed> $generated
     * @param list<string> $protectedPaths
     * @return array<string,mixed>
     */
    public function merge(array $existing, array $generated, array $protectedPaths): array
    {
        $merged = array_replace_recursive($existing, $generated);
        foreach ($protectedPaths as $path) {
            $segments = array_values(array_filter(explode('.', trim($path)), static fn (string $value): bool => $value !== ''));
            if ($segments === []) {
                continue;
            }
            $value = $this->read($existing, $segments, $found);
            if ($found) {
                $this->write($merged, $segments, $value);
            }
        }
        return $merged;
    }

    /** @param array<string,mixed> $source @param list<string> $segments */
    private function read(array $source, array $segments, ?bool &$found): mixed
    {
        $cursor = $source;
        foreach ($segments as $segment) {
            if (!is_array($cursor) || !array_key_exists($segment, $cursor)) {
                $found = false;
                return null;
            }
            $cursor = $cursor[$segment];
        }
        $found = true;
        return $cursor;
    }

    /** @param array<string,mixed> $target @param list<string> $segments */
    private function write(array &$target, array $segments, mixed $value): void
    {
        $cursor =& $target;
        foreach ($segments as $index => $segment) {
            if ($index === array_key_last($segments)) {
                $cursor[$segment] = $value;
                return;
            }
            if (!isset($cursor[$segment]) || !is_array($cursor[$segment])) {
                $cursor[$segment] = [];
            }
            $cursor =& $cursor[$segment];
        }
    }
}
