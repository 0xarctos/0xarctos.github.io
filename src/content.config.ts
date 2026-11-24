import { defineCollection, type Loader } from 'astro:content';
import { z } from 'astro/zod';
import { join, posix, resolve } from 'node:path';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import {
	ARCHS_FILE,
	LINKINGS,
	MITIGATIONS_FILE,
	VULNERABILITIES_FILE,
	TAGS_FILE,
	WRITEUPS_DIR,
	listScripts,
	parseScript,
	readAllowedList,
	readScript,
	slugify,
} from './lib/writeups';

/** Loads every src/writeups/<Event>/<challenge>.py as one write-up entry. */
function writeupsLoader(): Loader {
	return {
		name: 'writeups-loader',
		async load({ store, parseData, renderMarkdown, watcher, logger }) {
			const sync = async () => {
				store.clear();
				const allowedTags = new Set(readAllowedList(TAGS_FILE));
				const allowedArchs = new Set(readAllowedList(ARCHS_FILE));
				const allowedGaps = new Set(readAllowedList(MITIGATIONS_FILE));
				const allowedVulns = new Set(readAllowedList(VULNERABILITIES_FILE));
				const check = (values: string[], allowed: Set<string>, what: string, file: string) => {
					const unknown = values.filter((v) => !allowed.has(v));
					if (unknown.length) {
						throw new Error(`unknown ${what}: ${unknown.join(', ')}. Fix the typo or add them to ${file}.`);
					}
				};
				for (const path of listScripts()) {
					try {
						const { meta, notes, code } = parseScript(readScript(path));
						if (!code.trim()) throw new Error('no code after the metadata docstring');
						const id = slugify(path);
						const data = await parseData({
							id,
							data: { ...meta, folder: posix.dirname(path), script: posix.basename(path) },
						});
						check([data.arch], allowedArchs, 'arch', ARCHS_FILE);
						check(data.tags, allowedTags, 'tag(s)', TAGS_FILE);
						check(data.mitigation_gaps, allowedGaps, 'mitigation gap(s)', MITIGATIONS_FILE);
						check(data.vulnerabilities, allowedVulns, 'vulnerability(ies)', VULNERABILITIES_FILE);
						store.set({
							id,
							data,
							body: code,
							filePath: join(WRITEUPS_DIR, path),
							rendered: notes ? await renderMarkdown(notes) : undefined,
						});
					} catch (err) {
						logger.error(`${path}: ${(err as Error).message}`);
						throw err;
					}
				}
			};
			await sync();

			const root = resolve(WRITEUPS_DIR);
			watcher?.add(root);
			watcher?.on('all', (_event, changed) => {
				if (resolve(changed).startsWith(root)) sync().catch(() => {});
			});
		},
	};
}

const tag = z.string().trim().toLowerCase().min(1);

export const collections = {
	docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
	writeups: defineCollection({
		loader: writeupsLoader(),
		// Strict: any missing required key or any unexpected key fails the build.
		schema: z.strictObject({
			title: z.string().min(1),
			ctf: z.string().min(1),
			category: z.string().trim().toLowerCase().min(1),
			difficulty: z.number().int().min(1).max(5),
			arch: tag,
			linking: z.enum(LINKINGS),
			// Missing or partial mitigations, [] when the binary is fully hardened.
			mitigation_gaps: z.array(tag),
			// Bugs found in the binary and exploited.
			vulnerabilities: z.array(tag).min(1),
			tags: z.array(tag).min(1),
			// Added by the loader, not written in the script.
			folder: z.string(),
			script: z.string(),
		}),
	}),
};
