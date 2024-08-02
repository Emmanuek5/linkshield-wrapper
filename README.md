# linkshield-wrapper

To install dependencies:

```bash
bun install
```

To Use:
```ts
import { LinkShield } from 'linkshield-wrapper';

const linkShield = new LinkShield({
    apiKey: 'API_KEY',
    cacheFile: 'cache.json',
});

linkShiled.checkUrl('https://example.com').then((result) => {
    console.log(result);
});

```

This project was created using `bun init` in bun v1.1.6. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.
