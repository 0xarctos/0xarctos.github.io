/**
 * Write-ups are plain Python scripts dropped in src/writeups/<Event>/<challenge>.py.
 * Their metadata lives in the module docstring at the top of the script:
 *
 *   """
 *   title: Blue Market
 *   ctf: WolvCTF 2026
 *   category: pwn
 *   difficulty: 2              # 1 (very easy) to 5 (insane)
 *   arch: amd64                # listed in src/writeups/archs.yml
 *   linking: dynamic           # static | dynamic
 *   mitigation_gaps: [no-pie, no-canary]   # each listed in src/writeups/mitigations.yml, [] if none
 *   vulnerabilities: [stack-overflow]      # each listed in src/writeups/vulnerabilities.yml
 *   tags: [rop, ret2win]       # each tag must be listed in src/writeups/tags.yml
 *   ---
 *   Optional notes in Markdown, displayed above the script.
 *   """
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';

export const WRITEUPS_DIR = 'src/writeups';
export const TAGS_FILE = join(WRITEUPS_DIR, 'tags.yml');
export const MITIGATIONS_FILE = join(WRITEUPS_DIR, 'mitigations.yml');
export const VULNERABILITIES_FILE = join(WRITEUPS_DIR, 'vulnerabilities.yml');
export const ARCHS_FILE = join(WRITEUPS_DIR, 'archs.yml');

export const LINKINGS = ['static', 'dynamic'] as const;

/** Reads a YAML list of allowed values (tags.yml, archs.yml, ...). */
export function readAllowedList(file: string): string[] {
	const values = parseYaml(readFileSync(file, 'utf8'));
	if (!Array.isArray(values) || !values.every((t) => typeof t === 'string')) {
		throw new Error(`${file} must be a YAML list of strings`);
	}
	return values.map((t) => t.trim().toLowerCase());
}

export interface ParsedScript {
	/** Raw metadata, validated later by the collection schema. */
	meta: Record<string, unknown>;
	/** Markdown found after the "---" line of the docstring. */
	notes: string;
	/** The script without its metadata docstring. */
	code: string;
}

// Optional shebang / encoding / comment lines, then a """ or ''' docstring.
const DOCSTRING = /^((?:[ \t]*#[^\n]*\n|[ \t]*\n)*)[ \t]*[rRuU]?("""|''')([\s\S]*?)\2[ \t]*\n?/;

export function parseScript(source: string): ParsedScript {
	source = source.replace(/\r\n/g, '\n');
	const match = DOCSTRING.exec(source);
	if (!match) throw new Error(`missing metadata docstring at the top of the script`);

	const [whole, before, , docstring] = match;
	const [yamlPart, ...rest] = docstring.split(/^---[ \t]*$/m);
	const meta = parseYaml(dedent(yamlPart)) ?? {};
	if (typeof meta !== 'object' || Array.isArray(meta)) {
		throw new Error(`docstring metadata must be "key: value" lines`);
	}

	const code = (before + source.slice(whole.length)).replace(/^\s*\n/, '').trimEnd() + '\n';
	return { meta, notes: dedent(rest.join('---')).trim(), code };
}

function dedent(text: string) {
	const lines = text.split('\n');
	const indents = lines.filter((l) => l.trim()).map((l) => l.match(/^[ \t]*/)![0].length);
	const indent = indents.length ? Math.min(...indents) : 0;
	return lines.map((l) => l.slice(indent)).join('\n');
}

/** All .py files under src/writeups, as paths relative to it ("WolvCTF_2026/blue_market.py"). */
export function listScripts(dir = WRITEUPS_DIR): string[] {
	const walk = (d: string): string[] =>
		readdirSync(d, { withFileTypes: true }).flatMap((e) =>
			e.isDirectory() ? walk(join(d, e.name)) : e.name.endsWith('.py') ? [join(d, e.name)] : [],
		);
	try {
		statSync(dir);
	} catch {
		return [];
	}
	return walk(dir)
		.map((p) => relative(dir, p).split(sep).join('/'))
		.sort();
}

export function readScript(path: string) {
	return readFileSync(join(WRITEUPS_DIR, path), 'utf8');
}

/** "WolvCTF_2026" -> "WolvCTF 2026" */
export const prettify = (name: string) => name.replace(/[_-]+/g, ' ').trim();

/** URL slug for a script path: "WolvCTF_2026/blue_market.py" -> "wolvctf-2026/blue-market" */
export const slugify = (path: string) =>
	path
		.replace(/\.py$/, '')
		.split('/')
		.map((part) => part.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''))
		.join('/');

export const DIFFICULTY_LABELS = ['', 'Very easy', 'Easy', 'Medium', 'Hard', 'Insane'];

/** Starlight badge variant per challenge category (sidebar and tables share this). */
export type BadgeVariant = 'danger' | 'note' | 'tip' | 'caution' | 'success' | 'default';
export const CATEGORY_BADGE_VARIANTS: Record<string, BadgeVariant> = {
	pwn: 'danger',
	rev: 'note',
	reverse: 'note',
	web: 'tip',
	crypto: 'caution',
	forensics: 'success',
};
export const categoryVariant = (category: string): BadgeVariant =>
	CATEGORY_BADGE_VARIANTS[category] ?? 'default';

/** Absolute URL of the avatar, the default social-embed image. */
export const AVATAR_OG_IMAGE = 'https://0xarctos.github.io/favicon.jpg';

/** Head tags setting og:image + twitter:image to `url` (for Starlight frontmatter.head). */
export const ogImageMeta = (url: string) =>
	[
		{ tag: 'meta', attrs: { property: 'og:image', content: url } },
		{ tag: 'meta', attrs: { name: 'twitter:image', content: url } },
	] as const;
