import { formBuilder } from '@payloadcms/plugin-form-builder';
import { nestedDocs } from '@payloadcms/plugin-nested-docs';
import Users from './collections/Users';
import BlogPosts from './collections/BlogPosts';
import Resources from './collections/Resources';
import Videos from './collections/Videos';
import Programs from './collections/Programs';
import Recipes from './collections/Recipes';
import FAQs from './collections/FAQs';
import Testimonials from './collections/Testimonials';
import Media from './collections/Media';

export default buildConfig({
  serverURL: process.env.PAYLOAD_PUBLIC_SERVER_URL || 'http://localhost:4000',
  admin: {
    user: Users.slug,
    bundler: 'webpack',
    meta: {
      titleSuffix: '- Nutrition Platform Admin',
      favicon: '/favicon.ico',
      ogImage: '/og-image.jpg',
    },
    components: {
      graphics: {
        Logo: './components/Logo',
        Icon: './components/Icon',
      },
    },
  },
  collections: [
    Users,
    BlogPosts,
    Resources,
    Videos,
    Programs,
    Recipes,
    FAQs,
    Testimonials,
    Media,
  ],
  globals: [
    {
      slug: 'site-settings',
      label: 'Site Settings',
      fields: [
        {
          name: 'siteName',
          type: 'text',
          required: true,
        },
        {
          name: 'tagline',
          type: 'text',
        },
        {
          name: 'contact',
          type: 'group',
          fields: [
            {
              name: 'email',
              type: 'email',
              required: true,
            },
            {
              name: 'phone',
              type: 'text',
            },
            {
              name: 'whatsapp',
              type: 'text',
            },
          ],
        },
        {
          name: 'socialMedia',
          type: 'group',
          fields: [
            {
              name: 'instagram',
              type: 'text',
            },
            {
              name: 'facebook',
              type: 'text',
            },
            {
              name: 'youtube',
              type: 'text',
            },
            {
              name: 'twitter',
              type: 'text',
            },
          ],
        },
      ],
    },
    {
      slug: 'navigation',
      label: 'Navigation',
      fields: [
        {
          name: 'mainMenu',
          type: 'array',
          fields: [
            {
              name: 'label',
              type: 'text',
              required: true,
            },
            {
              name: 'url',
              type: 'text',
            },
            {
              name: 'submenu',
              type: 'array',
              fields: [
                {
                  name: 'label',
                  type: 'text',
                  required: true,
                },
                {
                  name: 'url',
                  type: 'text',
                  required: true,
                },
              ],
            },
          ],
        },
        {
          name: 'footerMenu',
          type: 'array',
          fields: [
            {
              name: 'label',
              type: 'text',
              required: true,
            },
            {
              name: 'url',
              type: 'text',
              required: true,
            },
          ],
        },
      ],
    },
  ],
  plugins: [
    cloudStorage({
      collections: {
        media: {
          adapter: s3Adapter({
            config: {
              endpoint: process.env.S3_ENDPOINT,
              credentials: {
                accessKeyId: process.env.S3_ACCESS_KEY,
                secretAccessKey: process.env.S3_SECRET_KEY,
              },
              region: process.env.S3_REGION,
            },
            bucket: process.env.S3_BUCKET || 'nutrition-platform',
          }),
        },
      },
    }),
    seo({
      collections: ['blog-posts', 'resources', 'programs'],
      tabbedUI: true,
      fields: [
        {
          name: 'metaTitle',
          type: 'text',
          maxLength: 60,
        },
        {
          name: 'metaDescription',
          type: 'textarea',
          maxLength: 160,
        },
        {
          name: 'metaKeywords',
          type: 'text',
        },
        {
          name: 'ogImage',
          type: 'upload',
          relationTo: 'media',
        },
      ],
    }),
    formBuilder({
      fields: {
        text: true,
        email: true,
        textarea: true,
        select: true,
        checkbox: true,
        radio: true,
        number: true,
      },
      formSubmissionOverrides: {
        fields: [
          {
            name: 'source',
            type: 'text',
          },
          {
            name: 'ipAddress',
            type: 'text',
          },
        ],
      },
    }),
    nestedDocs({
      collections: ['resources'],
      generateLabel: (_, doc) => doc.title as string,
      generateURL: (docs) => 
        docs.reduce((url, doc) => `${url}/${doc.slug}`, ''),
    }),
  ],
  typescript: {
    outputFile: path.resolve(__dirname, 'payload-types.ts'),
  },
  graphQL: {
    schemaOutputFile: path.resolve(__dirname, 'generated-schema.graphql'),
    disablePlaygroundInProduction: true,
  },
  cors: [
    process.env.CLIENT_URL || 'http://localhost:3000',
  ],
  csrf: [
    process.env.CLIENT_URL || 'http://localhost:3000',
  ],
  rateLimit: {
    max: 2000,
    trustProxy: true,
  },
});
```

#### 2. Blog Posts Collection
```typescript
// apps/admin/src/collections/BlogPosts.ts
import { CollectionConfig } from 'payload/types';
import { lexicalEditor } from '@payloadcms/richtext-lexical';

const BlogPosts: CollectionConfig = {
  slug: 'blog-posts',
  admin: {
    useAsTitle: 'title',
    defaultColumns: ['title', 'category', 'status', 'publishedAt'],
    group: 'Content',
  },
  access: {
    read: () => true,
    create: ({ req: { user } }) => user?.role === 'admin' || user?.role === 'editor',
    update: ({ req: { user } }) => user?.role === 'admin' || user?.role === 'editor',
    delete: ({ req: { user } }) => user?.role === 'admin',
  },
  hooks: {
    beforeChange: [
      ({ data, operation }) => {
        if (operation === 'create') {
          data.slug = data.title
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');
        }
        return data;
      },
    ],
    afterRead: [
      ({ doc }) => {
        // Calculate read time
        const wordsPerMinute = 200;
        const wordCount = doc.content?.split(' ').length || 0;
        doc.readTime = Math.ceil(wordCount / wordsPerMinute);
        return doc;
      },
    ],
  },
  fields: [
    {
      name: 'title',
      type: 'text',
      required: true,
    },
    {
      name: 'slug',
      type: 'text',
      unique: true,
      admin: {
        position: 'sidebar',
      },
    },
    {
      name: 'excerpt',
      type: 'textarea',
      maxLength: 200,
    },
    {
      name: 'content',
      type: 'richText',
      required: true,
      editor: lexicalEditor({
        features: [
          'bold',
          'italic',
          'underline',
          'strikethrough',
          'code',
          'link',
          'orderedList',
          'unorderedList',
          'heading',
          'blockquote',
          'upload',
          'indent',
          'align',
          'horizontalRule',
        ],
      }),
    },
    {
      name: 'featuredImage',
      type: 'upload',
      relationTo: 'media',
      required: true,
    },
    {
      name: 'category',
      type: 'select',
      required: true,
      options: [
        { label: 'Nutrition', value: 'nutrition' },
        { label: 'Gut Health', value: 'gut-health' },
        { label: 'Hormones', value: 'hormones' },
        { label: 'Recipes', value: 'recipes' },
        { label: 'Lifestyle', value: 'lifestyle' },
        { label: 'Success Stories', value: 'success-stories' },
      ],
    },
    {
      name: 'tags',
      type: 'array',
      fields: [
        {
          name: 'tag',
          type: 'text',
        },
      ],
    },
    {
      name: 'author',
      type: 'relationship',
      relationTo: 'users',
      required: true,
      admin: {
        position: 'sidebar',
      },
    },
    {
      name: 'status',
      type: 'select',
      required: true,
      defaultValue: 'draft',
      options: [
        { label: 'Draft', value: 'draft' },
        { label: 'Published', value: 'published' },
        { label: 'Archived', value: 'archived' },
      ],
      admin: {
        position: 'sidebar',
      },
    },
    {
      name: 'publishedAt',
      type: 'date',
      admin: {
        position: 'sidebar',
        date: {
          pickerAppearance: 'dayAndTime',
        },
      },
    },
    {
      name: 'relatedPosts',
      type: 'relationship',
      relationTo: 'blog-posts',
      hasMany: true,
      maxRows: 3,
    },
    {
      name: 'cta',
      type: 'group',
      fields: [
        {
          name: 'enabled',
          type: 'checkbox',
          defaultValue: true,
        },
        {
          name: 'title',
          type: 'text',
          defaultValue: 'Ready to transform your health?',
        },
        {
          name: 'buttonText',
          type: 'text',
          defaultValue: 'Book a Consultation',
        },
        {
          name: 'buttonLink',
          type: 'text',
          defaultValue: '/book-consultation',
        },
      ],
    },
  ],
  versions: {
    drafts: true,
  },
  timestamps: true,
};

export default BlogPosts;
```

#### 3. Resources Collection
```typescript
// apps/admin/src/collections/Resources.ts
import { CollectionConfig } from 'payload/types';

const Resources: CollectionConfig = {
  slug: 'resources',
  admin: {
    useAsTitle: 'title',
    defaultColumns: ['title', 'type', 'category', 'downloadCount'],
    group: 'Content',
  },
  access: {
    read: ({ req: { user } }) => {
      // Public resources available to all
      // Private resources need authentication
      return {
        or: [
          { isPublic: { equals: true } },
          { _and: [
            { isPublic: { equals: false } },
            { createdBy: { equals: user?.id } },
          ]},
        ],
      };
    },
  },
  fields: [
    {
      name: 'title',
      type: 'text',
      required: true,
    },
    {
      name: 'description',
      type: 'textarea',
      maxLength: 500,
    },
    {
      name: 'type',
      type: 'select',
      required: true,
      options: [
        { label: 'PDF Guide', value: 'pdf' },
        { label: 'Video', value: 'video' },
        { label: 'Calculator', value: 'calculator' },
        { label: 'Tracker Template', value: 'tracker' },
        { label: 'Meal Plan', value: 'meal_plan' },
        { label: 'Recipe Collection', value: 'recipe_collection' },
      ],
    },
    {
      name: 'category',
      type: 'select',
      required: true,
      options: [
        { label: 'Getting Started', value: 'getting-started' },
        { label: 'Meal Planning', value: 'meal-planning' },
        { label: 'Gut Health', value: 'gut-health' },
        { label: 'Hormones', value: 'hormones' },
        { label: 'Weight Management', value: 'weight-management' },
        { label: 'Tools & Calculators', value: 'tools' },
      ],
    },
    {
      name: 'file',
      type: 'upload',
      relationTo: 'media',
      required: true,
    },
    {
      name: 'thumbnail',
      type: 'upload',
      relationTo: 'media',
    },
    {
      name: 'isPublic',
      type: 'checkbox',
      defaultValue: true,
      admin: {
        position: 'sidebar',
      },
    },
    {
      name: 'requiresAuth',
      type: 'checkbox',
      defaultValue: false,
      admin: {
        position: 'sidebar',
      },
    },
    {
      name: 'accessLevel',
      type: 'select',
      options: [
        { label: 'Free', value: 'free' },
        { label: 'Registered Users', value: 'registered' },
        { label: 'Program Members', value: 'program' },
        { label: 'Premium', value: 'premium' },
      ],
      defaultValue: 'free',
      admin: {
        position: 'sidebar',
      },
    },
    {
      name: 'tags',
      type: 'array',
      fields: [
        {
          name: 'tag',
          type: 'text',
        },
      ],
    },
    {
      name: 'downloadCount',
      type: 'number',
      defaultValue: 0,
      admin: {
        readOnly: true,
        position: 'sidebar',
      },
    },
    {
      name: 'leadMagnet',
      type: 'group',
      fields: [
        {
          name: 'enabled',
          type: 'checkbox',
          defaultValue: false,
        },
        {
          name: 'emailRequired',
          type: 'checkbox',
          defaultValue: true,
        },
        {
          name: 'followUpEmail',
          type: 'relationship',
          relationTo: 'email-templates',
        },
      ],
    },
  ],
  hooks: {
    afterOperation: [
      async ({ operation, result }) => {
        if (operation === 'findByID' && result) {
          // Increment download count
          await payload.update({
            collection: 'resources',
            id: result.id,
            data: {
              downloadCount: (result.downloadCount || 0) + 1,
            },
          });
        }
        return result;
      },
    ],
  },
  timestamps: true,
};

export default Resources;
```

### Day 4-5: Content API Integration

#### 1. Content Service
```typescript
// services/content/src/services/content.service.ts
import { Payload } from 'payload';
import { cacheManager } from '../utils/cache';
import { SearchService } from './search.service';

export class ContentService {
  private static payload: Payload;
  private static readonly CACHE_PREFIX = 'content:';
  private static readonly CACHE_TTL = 3600; // 1 hour

  static initialize(payload: Payload) {
    this.payload = payload;
  }

  static async getBlogPosts(options: {
    page?: number;
    limit?: number;
    category?: string;
    tag?: string;
    search?: string;
  }) {
    const cacheKey = `${this.CACHE_PREFIX}blogs:${JSON.stringify(options)}`;
    const cached = await cacheManager.get(cacheKey);

    if (cached) {
      return JSON.parse(cached);
    }

    const where: any = {
      status: { equals: 'published' },
    };

    if (options.category) {
      where.category = { equals: options.category };
    }

    if (options.tag) {
      where['tags.tag'] = { contains: options.tag };
    }

    const result = await this.payload.find({
      collection: 'blog-posts',
      where,
      page: options.page || 1,
      limit: options.limit || 10,
      sort: '-publishedAt',
      depth: 1,
    });

    // Apply search if provided
    if (options.search) {
      const searchResults = await SearchService.searchContent(
        options.search,
        'blog-posts'
      );
      
      // Filter results based on search
      result.docs = result.docs.filter((doc: any) =>
        searchResults.includes(doc.id)
      );
      result.totalDocs = result.docs.length;
    }

    await cacheManager.set(cacheKey, JSON.stringify(result), this.CACHE_TTL);

    return result;
  }

  static async getBlogPost(slug: string) {
    const cacheKey = `${this.CACHE_PREFIX}blog:${slug}`;
    const cached = await cacheManager.get(cacheKey);

    if (cached) {
      return JSON.parse(cached);
    }

    const result = await this.payload.find({
      collection: 'blog-posts',
      where: {
        slug: { equals: slug },
        status: { equals: 'published' },
      },
      depth: 2,
    });

    if (result.docs.length === 0) {
      return null;
    }

    const post = result.docs[0];

    // Increment view count
    await this.incrementViewCount('blog-posts', post.id);

    // Get related posts
    const relatedPosts = await this.getRelatedContent(post);
    post.relatedPosts = relatedPosts;

    await cacheManager.set(cacheKey, JSON.stringify(post), this.CACHE_TTL);

    return post;
  }

  static async getResources(options: {
    type?: string;
    category?: string;
    accessLevel?: string;
    userId?: string;
  }) {
    const where: any = {};

    if (options.type) {
      where.type = { equals: options.type };
    }

    if (options.category) {
      where.category = { equals: options.category };
    }

    // Handle access control
    if (!options.userId) {
      where.isPublic = { equals: true };
      where.accessLevel = { equals: 'free' };
    } else {
      // Complex access logic based on user's subscriptions
      where.or = [
        { isPublic: { equals: true } },
        { accessLevel: { equals: 'registered' } },
        // Add more conditions based on user's access
      ];
    }

    const result = await this.payload.find({
      collection: 'resources',
      where,
      sort: '-createdAt',
      depth: 1,
    });

    return result;
  }

  static async getResource(id: string, userId?: string) {
    const resource = await this.payload.findByID({
      collection: 'resources',
      id,
      depth: 1,
    });

    if (!resource) {
      throw new Error('Resource not found');
    }

    // Check access
    if (!this.hasResourceAccess(resource, userId)) {
      throw new Error('Access denied');
    }

    // Generate signed URL for file download
    const downloadUrl = await this.generateDownloadUrl(resource);

    return {
      ...resource,
      downloadUrl,
    };
  }

  static async getVideos(options: {
    page?: number;
    limit?: number;
    category?: string;
  }) {
    const where: any = {
      status: { equals: 'published' },
    };

    if (options.category) {
      where.category = { equals: options.category };
    }

    const result = await this.payload.find({
      collection: 'videos',
      where,
      page: options.page || 1,
      limit: options.limit || 10,
      sort: '-publishedAt',
      depth: 1,
    });

    return result;
  }

  static async searchContent(query: string, collections?: string[]) {
    const collectionsToSearch = collections || [
      'blog-posts',
      'resources',
      'videos',
      'recipes',
    ];

    const results = await Promise.all(
      collectionsToSearch.map(async (collection) => {
        const searchResults = await SearchService.searchContent(query, collection);
        
        const docs = await Promise.all(
          searchResults.slice(0, 5).map((id) =>
            this.payload.findByID({ collection, id, depth: 0 })
          )
        );

        return {
          collection,
          results: docs.filter(Boolean),
        };
      })
    );

    return results;
  }

  static async getRelatedContent(content: any) {
    // Get content with similar tags
    const tags = content.tags?.map((t: any) => t.tag) || [];
    
    if (tags.length === 0) {
      return [];
    }

    const result = await this.payload.find({
      collection: content.collection || 'blog-posts',
      where: {
        id: { not_equals: content.id },
        'tags.tag': { in: tags },
        status: { equals: 'published' },
      },
      limit: 4,
      sort: '-publishedAt',
      depth: 0,
    });

    return result.docs;
  }

  private static async incrementViewCount(collection: string, id: string) {
    try {
      const doc = await this.payload.findByID({ collection, id });
      
      await this.payload.update({
        collection,
        id,
        data: {
          viewCount: (doc.viewCount || 0) + 1,
        },
      });
    } catch (error) {
      console.error('Failed to increment view count:', error);
    }
  }

  private static hasResourceAccess(resource: any, userId?: string): boolean {
    if (resource.isPublic && resource.accessLevel === 'free') {
      return true;
    }

    if (!userId) {
      return false;
    }

    // Additional access checks based on user's subscriptions
    // This would check user's program enrollments, subscriptions, etc.
    
    return resource.accessLevel === 'registered';
  }

  private static async generateDownloadUrl(resource: any): Promise<string> {
    // Generate a signed URL that expires in 1 hour
    // This would integrate with your storage solution
    const baseUrl = process.env.STORAGE_URL;
    const expires = Date.now() + 3600000; // 1 hour
    
    // Generate signature
    const signature = this.generateSignature(resource.file.id, expires);
    
    return `${baseUrl}/download/${resource.file.id}?expires=${expires}&signature=${signature}`;
  }

  private static generateSignature(fileId: string, expires: number): string {
    // Implement signature generation for secure downloads
    const crypto = require('crypto');
    const secret = process.env.DOWNLOAD_SECRET;
    
    return crypto
      .createHmac('sha256', secret)
      .update(`${fileId}:${expires}`)
      .digest('hex');
  }
}
```

### Day 6-7: Search Implementation

#### 1. Search Service with MeiliSearch
```typescript
// services/content/src/services/search.service.ts
import { MeiliSearch, Index } from 'meilisearch';
import { prisma } from '@nutrition/database';

export class SearchService {
  private static client: MeiliSearch;
  private static indices: Map<string, Index> = new Map();

  static initialize() {
    this.client = new MeiliSearch({
      host: process.env.MEILISEARCH_HOST!,
      apiKey: process.env.MEILISEARCH_KEY!,
    });

    this.setupIndices();
  }

  private static async setupIndices() {
    const collections = [
      'blog-posts',
      'resources',
      'videos',
      'recipes',
      'programs',
    ];

    for (const collection of collections) {
      const index = this.client.index(collection);
      
      // Set searchable attributes
      await index.updateSearchableAttributes([
        'title',
        'content',
        'description',
        'tags',
        'category',
      ]);

      // Set filterable attributes
      await index.updateFilterableAttributes([
        'status',
        'category',
        'type',
        'accessLevel',
        'publishedAt',
      ]);

      // Set sortable attributes
      await index.updateSortableAttributes([
        'publishedAt',
        'viewCount',
        'downloadCount',
      ]);

      // Set ranking rules
      await index.updateRankingRules([
        'words',
        'typo',
        'proximity',
        'attribute',
        'sort',
        'exactness',
        'viewCount:desc',
      ]);

      this.indices.set(collection, index);
    }
  }

  static async indexContent(collection: string, documents: any[]) {
    const index = this.indices.get(collection);
    if (!index) {
      throw new Error(`Index for ${collection} not found`);
    }

    // Transform documents for indexing
    const transformedDocs = documents.map((doc) => ({
      id: doc.id,
      title: doc.title,
      content: this.extractTextContent(doc.content),
      description: doc.description || doc.excerpt,
      tags: doc.tags?.map((t: any) => t.tag).join(' ') || '',
      category: doc.category,
      type: doc.type,
      status: doc.status,
      publishedAt: doc.publishedAt,
      viewCount: doc.viewCount || 0,
      downloadCount: doc.downloadCount || 0,
    }));

    await index.addDocuments(transformedDocs);
  }

  static async searchContent(
    query: string,
    collection: string,
    filters?: any
  ): Promise<string[]> {
    const index = this.indices.get(collection);
    if (!index) {
      throw new Error(`Index for ${collection} not found`);
    }

    const searchParams: any = {
      limit: 20,
    };

    // Build filter string
    const filterConditions: string[] = [];
    
    if (filters?.category) {
      filterConditions.push(`category = "${filters.category}"`);
    }
    
    if (filters?.status) {
      filterConditions.push(`status = "${filters.status}"`);
    }
    
    if (filterConditions.length > 0) {
      searchParams.filter = filterConditions.join(' AND ');
    }

    const results = await index.search(query, searchParams);
    
    return results.hits.map((hit) => hit.id);
  }

  static async searchAcrossCollections(query: string, userId?: string) {
    const results = await this.client.multiSearch({
      queries: [
        {
          indexUid: 'blog-posts',
          q: query,
          filter: 'status = "published"',
          limit: 5,
        },
        {
          indexUid: 'resources',
          q: query,
          filter: userId ? '' : 'isPublic = true AND accessLevel = "free"',
          limit: 5,
        },
        {
          indexUid: 'programs',
          q: query,
          filter: 'isActive = true',
          limit: 3,
        },
        {
          indexUid: 'recipes',
          q: query,
          filter: 'status = "published"',
          limit: 5,
        },
      ],
    });

    return results.results.map((result, index) => ({
      collection: ['blog-posts', 'resources', 'programs', 'recipes'][index],
      hits: result.hits,
      totalHits: result.estimatedTotalHits,
    }));
  }

  static async getSuggestions(query: string) {
    // Get search suggestions based on popular searches
    const popularSearches = await prisma.searchLog.groupBy({
      by: ['query'],
      where: {
        query: {
          startsWith: query,
        },
      },
      _count: true,
      orderBy: {
        _count: {
          query: 'desc',
        },
      },
      take: 5,
    });

    return popularSearches.map((item) => item.query);
  }

  static async logSearch(query: string, userId?: string, results?: number) {
    await prisma.searchLog.create({
      data: {
        query,
        userId,
        resultsCount: results || 0,
        timestamp: new Date(),
      },
    });
  }

  private static extractTextContent(content: any): string {
    if (!content) return '';
    
    if (typeof content === 'string') {
      return content;
    }

    // Handle Lexical/Slate rich text content
    if (content.root?.children) {
      return this.extractTextFromNodes(content.root.children);
    }

    return '';
  }

  private static extractTextFromNodes(nodes: any[]): string {
    return nodes
      .map((node) => {
        if (node.type === 'text') {
          return node.text;
        }
        if (node.children) {
          return this.extractTextFromNodes(node.children);
        }
        return '';
      })
      .join(' ');
  }

  static async reindexCollection(collection: string) {
    const index = this.indices.get(collection);
    if (!index) {
      throw new Error(`Index for ${collection} not found`);
    }

    // Clear existing documents
    await index.deleteAllDocuments();

    // Fetch all documents from database
    let page = 1;
    const limit = 100;
    let hasMore = true;

    while (hasMore) {
      const documents = await prisma[collection].findMany({
        skip: (page - 1) * limit,
        take: limit,
      });

      if (documents.length === 0) {
        hasMore = false;
        break;
      }

      await this.indexContent(collection, documents);
      page++;
    }
  }
}
```

## Week 8: Notification System & WhatsApp Integration

### Day 1-3: Notification Service

#### 1. Notification Controller
```typescript
// services/notification/src/controllers/notification.controller.ts
import { Request, Response, NextFunction } from 'express';
import { NotificationService } from '../services/notification.service';
import { AppError } from '../utils/errors';

export class NotificationController {
  static async sendNotification(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId, type, template, data, schedule } = req.body;

      const notification = await NotificationService.sendNotification({
        userId,
        type,
        template,
        data,
        schedule,
      });

      res.json({
        success: true,
        message: 'Notification sent successfully',
        data: notification,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUserNotifications(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { status, page = 1, limit = 20 } = req.query;

      const notifications = await NotificationService.getUserNotifications(userId, {
        status: status as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: notifications,
      });
    } catch (error) {
      next(error);
    }
  }

  static async markAsRead(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      await NotificationService.markAsRead(id, userId);

      res.json({
        success: true,
        message: 'Notification marked as read',
      });
    } catch (error) {
      next(error);
    }
  }

  static async markAllAsRead(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      await NotificationService.markAllAsRead(userId);

      res.json({
        success: true,
        message: 'All notifications marked as read',
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const preferences = await NotificationService.getPreferences(userId);

      res.json({
        success: true,
        data: preferences,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updatePreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const preferences = req.body;

      await NotificationService.updatePreferences(userId, preferences);

      res.json({
        success: true,
        message: 'Preferences updated successfully',
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Notification Service
```typescript
// services/notification/src/services/notification.service.ts
import { prisma } from '@nutrition/database';
import { EmailService } from './channels/email.service';
import { SMSService } from './channels/sms.service';
import { WhatsAppService } from './channels/whatsapp.service';
import { PushService } from './channels/push.service';
import { TemplateService } from './template.service';
import { Queue } from 'bull';

interface NotificationData {
  userId: string;
  type: 'email' | 'sms' | 'whatsapp' | 'push' | 'in-app';
  template: string;
  data: any;
  schedule?: Date;
}

export class NotificationService {
  private static notificationQueue = new Queue('notifications', {
    redis: {
      host: process.env.REDIS_HOST,
      port: Number(process.env.REDIS_PORT),
      password: process.env.REDIS_PASSWORD,
    },
  });

  static async initialize() {
    // Process notification queue
    this.notificationQueue.process(async (job) => {
      const { notification } = job.data;
      await this.processNotification(notification);
    });

    // Handle failed jobs
    this.notificationQueue.on('failed', (job, err) => {
      console.error(`Notification job ${job.id} failed:`, err);
      // Log to error tracking service
    });
  }

  static async sendNotification(data: NotificationData) {
    // Get user preferences
    const preferences = await this.getPreferences(data.userId);
    
    // Check if user has opted out of this type
    if (!this.isNotificationEnabled(preferences, data.type, data.template)) {
      return null;
    }

    // Create notification record
    const notification = await prisma.notification.create({
      data: {
        userId: data.userId,
        type: data.type,
        category: this.getCategoryFromTemplate(data.template),
        title: await TemplateService.getTitle(data.template, data.data),
        content: await TemplateService.getContent(data.template, data.data),
        data: data.data,
        status: 'PENDING',
      },
    });

    // Schedule or send immediately
    if (data.schedule && data.schedule > new Date()) {
      await this.notificationQueue.add(
        'scheduled-notification',
        { notification },
        { delay: data.schedule.getTime() - Date.now() }
      );
    } else {
      await this.notificationQueue.add('send-notification', { notification });
    }

    return notification;
  }

  private static async processNotification(notification: any) {
    try {
      let result;

      switch (notification.type) {
        case 'email':
          result = await EmailService.send(notification);
          break;
        case 'sms':
          result = await SMSService.send(notification);
          break;
        case 'whatsapp':
          result = await WhatsAppService.send(notification);
          break;
        case 'push':
          result = await PushService.send(notification);
          break;
        case 'in-app':
          // In-app notifications are already stored
          result = { success: true };
          break;
        default:
          throw new Error(`Unknown notification type: ${notification.type}`);
      }

      // Update notification status
      await prisma.notification.update({
        where: { id: notification.id },
        data: {
          status: result.success ? 'SENT' : 'FAILED',
          sentAt: result.success ? new Date() : null,
          error: result.error,
        },
      });
    } catch (error) {
      await prisma.notification.update({
        where: { id: notification.id },
        data: {
          status: 'FAILED',
          error: error.message,
        },
      });
      throw error;
    }
  }

  static async getUserNotifications(userId: string, options: {
    status?: string;
    page: number;
    limit: number;
  }) {
    const where: any = {
      userId,
      type: 'in-app',
    };

    if (options.status) {
      where.status = options.status;
    }

    const [notifications, total] = await Promise.all([
      prisma.notification.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
      }),
      prisma.notification.count({ where }),
    ]);

    const unreadCount = await prisma.notification.count({
      where: {
        userId,
        type: 'in-app',
        readAt: null,
      },
    });

    return {
      notifications,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
      unreadCount,
    };
  }

  static async markAsRead(notificationId: string, userId: string) {
    await prisma.notification.update({
      where: {
        id: notificationId,
        userId,
      },
      data: {
        readAt: new Date(),
      },
    });
  }

  static async markAllAsRead(userId: string) {
    await prisma.notification.updateMany({
      where: {
        userId,
        type: 'in-app',
        readAt: null,
      },
      data: {
        readAt: new Date(),
      },
    });
  }

  static async getPreferences(userId: string) {
    let preferences = await prisma.notificationPreferences.findUnique({
      where: { userId },
    });

    if (!preferences) {
      // Create default preferences
      preferences = await prisma.notificationPreferences.create({
        data: {
          userId,
          email: {
            marketing: true,
            transactional: true,
            reminders: true,
            updates: true,
          },
          sms: {
            reminders: true,
            urgent: true,
          },
          whatsapp: {
            reminders: true,
            updates: true,
          },
          push: {
            all: true,
          },
        },
      });
    }

    return preferences;
  }

  static async updatePreferences(userId: string, preferences: any) {
    await prisma.notificationPreferences.upsert({
      where: { userId },
      update: preferences,
      create: {
        userId,
        ...preferences,
      },
    });
  }

  private static isNotificationEnabled(
    preferences: any,
    type: string,
    template: string
  ): boolean {
    const category = this.getCategoryFromTemplate(template);
    
    if (!preferences[type]) {
      return true; // Default to enabled if no preference set
    }

    return preferences[type][category] !== false;
  }

  private static getCategoryFromTemplate(template: string): string {
    const templateCategories: Record<string, string> = {
      welcome: 'marketing',
      consultation_reminder: 'reminders',
      payment_success: 'transactional',
      program_update: 'updates',
      // ... more mappings
    };

    return templateCategories[template] || 'updates';
  }

  static async sendBulkNotifications(
    userIds: string[],
    template: string,
    data: any
  ) {
    const jobs = userIds.map((userId) => ({
      name: 'send-notification',
      data: {
        notification: {
          userId,
          type: 'email',
          template,
          data,
        },
      },
    }));

    await this.notificationQueue.addBulk(jobs);
  }

  static async scheduleRecurringNotification(
    userId: string,
    template: string,
    data: any,
    schedule: string // Cron expression
  ) {
    await this.notificationQueue.add(
      'recurring-notification',
      {
        userId,
        template,
        data,
      },
      {
        repeat: { cron: schedule },
      }
    );
  }
}
```

### Day 4-5: WhatsApp Business Integration

#### 1. WhatsApp Service
```typescript
// services/notification/src/services/channels/whatsapp.service.ts
import axios from 'axios';
import { prisma } from '@nutrition/database';
import crypto from 'crypto';

interface WhatsAppMessage {
  to: string;
  type: 'text' | 'template' | 'interactive' | 'media';
  content: any;
}

export class WhatsAppService {
  private static readonly API_URL = process.env.WHATSAPP_API_URL;
  private static readonly PHONE_ID = process.env.WHATSAPP_PHONE_ID;
  private static readonly TOKEN = process.env.WHATSAPP_TOKEN;
  private static readonly WEBHOOK_TOKEN = process.env.WHATSAPP_WEBHOOK_TOKEN;

  static async send(notification: any): Promise<{ success: boolean; error?: string }> {
    try {
      // Get user's WhatsApp number
      const user = await prisma.user.findUnique({
        where: { id: notification.userId },
        select: { phone: true },
      });

      if (!user?.phone) {
        throw new Error('User phone number not found');
      }

      // Format phone number
      const formattedPhone = this.formatPhoneNumber(user.phone);

      // Send message based on notification template
      const message = await this.buildMessage(notification);
      
      const response = await this.sendMessage({
        to: formattedPhone,
        ...message,
      });

      return { success: true };
    } catch (error) {
      console.error('WhatsApp send error:', error);
      return { success: false, error: error.message };
    }
  }

  static async sendMessage(message: WhatsAppMessage) {
    const endpoint = `${this.API_URL}/${this.PHONE_ID}/messages`;

    const payload = this.buildPayload(message);

    const response = await axios.post(endpoint, payload, {
      headers: {
        'Authorization': `Bearer ${this.TOKEN}`,
        'Content-Type': 'application/json',
      },
    });

    return response.data;
  }

  private static buildPayload(message: WhatsAppMessage) {
    const basePayload = {
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: message.to,
    };

    switch (message.type) {
      case 'text':
        return {
          ...basePayload,
          type: 'text',
          text: {
            preview_url: true,
            body: message.content,
          },
        };

      case 'template':
        return {
          ...basePayload,
          type: 'template',
          template: {
            name: message.content.name,
            language: {
              code: message.content.language || 'en',
            },
            components: message.content.components || [],
          },
        };

      case 'interactive':
        return {
          ...basePayload,
          type: 'interactive',
          interactive: message.content,
        };

      case 'media':
        return {
          ...basePayload,
          type: message.content.type, // image, document, etc.
          [message.content.type]: {
            link: message.content.url,
            caption: message.content.caption,
          },
        };

      default:
        throw new Error(`Unsupported message type: ${message.type}`);
    }
  }

  private static async buildMessage(notification: any) {
    // Map notification templates to WhatsApp templates
    const templateMap: Record<string, any> = {
      consultation_reminder: {
        type: 'template',
        content: {
          name: 'consultation_reminder',
          components: [
            {
              type: 'body',
              parameters: [
                {
                  type: 'text',
                  text: notification.data.nutritionistName,
                },
                {
                  type: 'text',
                  text: notification.data.time,
                },
              ],
            },
            {
              type: 'button',
              sub_type: 'url',
              index: '0',
              parameters: [
                {
                  type: 'text',
                  text: notification.data.meetingId,
                },
              ],
            },
          ],
        },
      },
      payment_success: {
        type: 'text',
        content: `Payment of ₹${notification.data.amount} received successfully! Your invoice has been sent to your email.`,
      },
      welcome: {
        type: 'interactive',
        content: {
          type: 'button',
          body: {
            text: `Welcome to Nutrition Platform, ${notification.data.firstName}! 🌱\n\nI'm here to help you with:\n• Booking consultations\n• Program information\n• Health tips\n• Quick answers`,
          },
          action: {
            buttons: [
              {
                type: 'reply',
                reply: {
                  id: 'book_consultation',
                  title: 'Book Consultation',
                },
              },
              {
                type: 'reply',
                reply: {
                  id: 'view_programs',
                  title: 'View Programs',
                },
              },
              {
                type: 'reply',
                reply: {
                  id: 'health_quiz',
                  title: 'Take Quiz',
                },
              },
            ],
          },
        },
      },
    };

    const template = templateMap[notification.data.template];
    if (!template) {
      // Default to text message
      return {
        type: 'text',
        content: notification.content,
      };
    }

    return template;
  }

  static async handleWebhook(req: any) {
    // Verify webhook
    if (!this.verifyWebhook(req)) {
      throw new Error('Invalid webhook signature');
    }

    const { entry } = req.body;

    for (const item of entry) {
      const { changes } = item;

      for (const change of changes) {
        if (change.field === 'messages') {
          await this.processMessages(change.value.messages);
        }
      }
    }
  }

  private static verifyWebhook(req: any): boolean {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) {
      return false;
    }

    const payload = JSON.stringify(req.body);
    const expectedSignature = crypto
      .createHmac('sha256', this.WEBHOOK_TOKEN)
      .update(payload)
      .digest('hex');

    return `sha256=${expectedSignature}` === signature;
  }

  private static async processMessages(messages: any[]) {
    for (const message of messages) {
      try {
        await this.handleIncomingMessage(message);
      } catch (error) {
        console.error('Error processing message:', error);
      }
    }
  }

  private static async handleIncomingMessage(message: any) {
    const { from, type, ...content } = message;

    // Find user by phone number
    const user = await prisma.user.findFirst({
      where: {
        phone: { endsWith: from.substring(2) }, // Remove country code
      },
    });

    if (!user) {
      // Send welcome message for new users
      await this.sendMessage({
        to: from,
        type: 'text',
        content: 'Welcome! Please register on our website to access all features.',
      });
      return;
    }

    // Process based on message type
    switch (type) {
      case 'text':
        await this.handleTextMessage(user.id, content.text.body);
        break;
      case 'interactive':
        await this.handleInteractiveMessage(user.id, content.interactive);
        break;
      default:
        await this.sendMessage({
          to: from,
          type: 'text',
          content: 'Sorry, I can only process text messages at the moment.',
        });
    }
  }

  private static async handleTextMessage(userId: string, text: string) {
    // Simple keyword-based responses
    const lowerText = text.toLowerCase();

    if (lowerText.includes('consultation') || lowerText.includes('book')) {
      await this.sendConsultationOptions(userId);
    } else if (lowerText.includes('program')) {
      await this.sendProgramList(userId);
    } else if (lowerText.includes('help')) {
      await this.sendHelpMenu(userId);
    } else {
      // Use NLP or forward to support
      await this.forwardToSupport(userId, text);
    }
  }

  private static async handleInteractiveMessage(userId: string, interactive: any) {
    const { type, button_reply, list_reply } = interactive;

    if (button_reply) {
      switch (button_reply.id) {
        case 'book_consultation':
          await this.sendConsultationOptions(userId);
          break;
        case 'view_programs':
          await this.sendProgramList(userId);
          break;
        case 'health_quiz':
          await this.sendQuizLink(userId);
          break;
      }
    }
  }

  private static async sendConsultationOptions(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { phone: true },
    });

    await this.sendMessage({
      to: user!.phone!,
      type: 'interactive',
      content: {
        type: 'list',
        header: {
          type: 'text',
          text: 'Book a Consultation',
        },
        body: {
          text: 'Choose a nutritionist to book your consultation:',
        },
        action: {
          button: 'View Options',
          sections: [
            {
              title: 'Available Nutritionists',
              rows: [
                {
                  id: 'nutritionist_1',
                  title: 'Dr. Sarah Johnson',
                  description: 'Gut Health Specialist',
                },
                {
                  id: 'nutritionist_2',
                  title: 'Dr. Priya Sharma',
                  description: 'Hormonal Balance Expert',
                },
              ],
            },
          ],
        },
      },
    });
  }

  private static async sendProgramList(userId: string) {
    // Fetch active programs
    const programs = await prisma.program.findMany({
      where: { isActive: true },
      take: 5,
    });

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { phone: true },
    });

    const programText = programs
      .map((p) => `*${p.name}*\n${p.shortDescription}\nPrice: ₹${p.price}`)
      .join('\n\n');

    await this.sendMessage({
      to: user!.phone!,
      type: 'text',
      content: `Our Current Programs:\n\n${programText}\n\nReply with program name for more details.`,
    });
  }

  private static async sendQuizLink(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { phone: true },
    });

    await this.sendMessage({
      to: user!.phone!,
      type: 'text',
      content: `Take our health assessment quiz to get personalized recommendations:\n\n${process.env.CLIENT_URL}/quiz/health-assessment?utm_source=whatsapp`,
    });
  }

  private static async sendHelpMenu(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { phone: true },
    });

    await this.sendMessage({
      to: user!.phone!,
      type: 'text',
      content: `Here's what I can help you with:\n\n📅 *Consultations* - Book or manage appointments\n📚 *Programs* - View our health programs\n🏥 *Health Tips* - Get daily wellness tips\n📊 *Progress* - Check your health journey\n💬 *Support* - Connect with our team\n\nJust type what you need help with!`,
    });
  }

  private static async forwardToSupport(userId: string, message: string) {
    // Create support ticket
    await prisma.supportTicket.create({
      data: {
        userId,
        channel: 'whatsapp',
        message,
        status: 'open',
      },
    });

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { phone: true },
    });

    await this.sendMessage({
      to: user!.phone!,
      type: 'text',
      content: `I've forwarded your message to our support team. They'll respond within 2-4 hours during business hours (9 AM - 6 PM IST).`,
    });
  }

  private static formatPhoneNumber(phone: string): string {
    // Remove all non-numeric characters
    const cleaned = phone.replace(/\D/g, '');
    
    // Add country code if not present
    if (!cleaned.startsWith('91')) {
      return `91${cleaned}`;
    }
    
    return cleaned;
  }
}
```

### Day 6-7: Email Templates & Campaigns

#### 1. Email Template Service
```typescript
// services/notification/src/services/template.service.ts
import handlebars from 'handlebars';
import mjml2html from 'mjml';
import { prisma } from '@nutrition/database';

export class TemplateService {
  private static templates = new Map<string, handlebars.TemplateDelegate>();
  private static mjmlTemplates = new Map<string, string>();

  static async initialize() {
    // Load templates from database or files
    await this.loadTemplates();

    // Register Handlebars helpers
    this.registerHelpers();
  }

  private static async loadTemplates() {
    // Load MJML templates
    this.mjmlTemplates.set('welcome', `
      <mjml>
        <mj-head>
          <mj-title>Welcome to {{companyName}}</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
          <mj-attributes>
            <mj-all font-family="Inter, Arial, sans-serif" />
            <mj-text font-size="16px" color="#333333" line-height="24px" />
          </mj-attributes>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-image src="{{logoUrl}}" width="150px" />
              <mj-spacer height="30px" />
              <mj-text font-size="28px" font-weight="700" align="center">
                Welcome, {{firstName}}! 🌱
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Your journey to better health starts today. We're excited to be part of your wellness transformation.
              </mj-text>
              <mj-spacer height="30px" />
              
              {{#each nextSteps}}
              <mj-wrapper padding="15px" background-color="#f8f9fa" border-radius="6px" margin-bottom="15px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    {{this.icon}} {{this.title}}
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    {{this.description}}
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    href="{{this.link}}"
                    padding="10px 20px"
                  >
                    {{this.buttonText}}
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              {{/each}}
              
              <mj-spacer height="30px" />
              <mj-divider border-color="#e5e7eb" />
              <mj-spacer height="30px" />
              
              <mj-text align="center" font-size="14px" color="#666666">
                Questions? Reply to this email or WhatsApp us at {{whatsappNumber}}
              </mj-text>
            </mj-column>
          </mj-section>
          
          <mj-section padding="20px">
            <mj-column>
              <mj-social font-size="15px" icon-size="30px" mode="horizontal">
                <mj-social-element name="instagram" href="{{socialLinks.instagram}}" />
                <mj-social-element name="facebook" href="{{socialLinks.facebook}}" />
                <mj-social-element name="youtube" href="{{socialLinks.youtube}}" />
              </mj-social>
              <mj-spacer height="20px" />
              <mj-text align="center" font-size="12px" color="#999999">
                © {{currentYear}} {{companyName}}. All rights reserved.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `);

    this.mjmlTemplates.set('consultation-reminder', `
      <mjml>
        <mj-head>
          <mj-title>Consultation Reminder</mj-title>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="24px" font-weight="700" align="center">
                Consultation Reminder 📅
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Hi {{firstName}},
              </mj-text>
              <mj-text>
                This is a reminder about your upcoming consultation:
              </mj-text>
              <mj-spacer height="20px" />
              
              <mj-wrapper background-color="#f0fdf4" padding="20px" border-radius="8px" border="1px solid #86efac">
                <mj-column>
                  <mj-text font-weight="600">
                    📅 Date: {{consultationDate}}
                  </mj-text>
                  <mj-text font-weight="600">
                    ⏰ Time: {{consultationTime}}
                  </mj-text>
                  <mj-text font-weight="600">
                    👩‍⚕️ With: {{nutritionistName}}
                  </mj-text>
                  <mj-text font-weight="600">
                    ⏱️ Duration: {{duration}} minutes
                  </mj-text>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="30px" />
              
              <mj-button 
                background-color="#10b981" 
                color="#ffffff" 
                font-size="16px"
                padding="15px 30px"
                href="{{meetingLink}}"
              >
                Join Consultation
              </mj-button>
              
              <mj-spacer height="20px" />
              
              <mj-text font-size="14px" color="#666666">
                <strong>Preparation Tips:</strong>
              </mj-text>
              <mj-text font-size="14px" color="#666666">
                • Have your recent health reports ready<br/>
                • Prepare a list of questions<br/>
                • Ensure stable internet connection<br/>
                • Find a quiet space for the call
              </mj-text>
              
              <mj-spacer height="30px" />
              
              <mj-text align="center" font-size="14px">
                Need to reschedule? <a href="{{rescheduleLink}}">Click here</a>
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `);

    // Compile templates
    for (const [name, mjml] of this.mjmlTemplates) {
      const { html } = mjml2html(mjml);
      this.templates.set(name, handlebars.compile(html));
    }
  }

  private static registerHelpers() {
    handlebars.registerHelper('formatCurrency', (amount: number, currency: string) => {
      return new Intl.NumberFormat('en-IN', {
        style: 'currency',
        currency: currency || 'INR',
      }).format(amount);
    });

    handlebars.registerHelper('formatDate', (date: Date, format: string) => {
      // Implement date formatting
      return new Date(date).toLocaleDateString('en-IN');
    });

    handlebars.registerHelper('eq', (a: any, b: any) => a === b);
    handlebars.registerHelper('ne', (a: any, b: any) => a !== b);
    handlebars.registerHelper('lt', (a: any, b: any) => a < b);
    handlebars.registerHelper('gt', (a: any, b: any) => a > b);
    handlebars.registerHelper('lte', (a: any, b: any) => a <= b);
    handlebars.registerHelper('gte', (a: any, b: any) => a >= b);
  }

  static async getTitle(templateName: string, data: any): Promise<string> {
    const titles: Record<string, string> = {
      welcome: 'Welcome to Your Wellness Journey! 🌱',
      'consultation-reminder': 'Consultation Reminder - {{consultationDate}}',
      'payment-success': 'Payment Received - Thank You!',
      'program-update': 'Update: {{programName}}',
      'weekly-tips': 'Your Weekly Wellness Tips 💚',
      'quiz-results': 'Your Health Assessment Results',
    };

    const titleTemplate = titles[templateName] || templateName;
    return handlebars.compile(titleTemplate)(data);
  }

  static async getContent(templateName: string, data: any): Promise<string> {
    const template = this.templates.get(templateName);
    
    if (!template) {
      throw new Error(`Template ${templateName} not found`);
    }

    // Add default data
    const defaultData = {
      companyName: 'Nutrition Platform',
      logoUrl: `${process.env.CLIENT_URL}/logo.png`,
      currentYear: new Date().getFullYear(),
      whatsappNumber: process.env.WHATSAPP_DISPLAY_NUMBER,
      socialLinks: {
        instagram: 'https://instagram.com/nutritionplatform',
        facebook: 'https://facebook.com/nutritionplatform',
        youtube: 'https://youtube.com/nutritionplatform',
      },
      ...data,
    };

    return template(defaultData);
  }

  static async renderTemplate(templateName: string, data: any): Promise<{
    subject: string;
    html: string;
    text: string;
  }> {
    const subject = await this.getTitle(templateName, data);
    const html = await this.getContent(templateName, data);
    
    // Generate text version
    const text = this.htmlToText(html);

    return { subject, html, text };
  }

  private static htmlToText(html: string): string {
    // Simple HTML to text conversion
    return html
      .replace(/<style[^>]*>.*?<\/style>/gi, '')
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  static async createCustomTemplate(name: string, mjml: string) {
    // Validate MJML
    const { html, errors } = mjml2html(mjml, { validationLevel: 'soft' });
    
    if (errors.length > 0) {
      throw new Error(`Invalid MJML: ${errors.map(e => e.message).join(', ')}`);
    }

    // Store template
    await prisma.emailTemplate.create({
      data: {
        name,
        mjml,
        html,
        createdAt: new Date(),
      },
    });

    // Add to cache
    this.mjmlTemplates.set(name, mjml);
    this.templates.set(name, handlebars.compile(html));
  }
}
```

## Week 9: Frontend Implementation - Next.js Setup

### Day 1-3: Next.js Project Structure

#### 1. Next.js Configuration
```typescript
// apps/web/next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  images: {
    domains: [
      'localhost',
      process.env.NEXT_PUBLIC_API_URL,
      process.env.NEXT_PUBLIC_CDN_URL,
      'images.unsplash.com', // For development
    ],
    formats: ['image/avif', 'image/webp'],
  },
  experimental: {
    appDir: true,
    serverActions: true,
  },
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL,
    NEXT_PUBLIC_GA_ID: process.env.NEXT_PUBLIC_GA_ID,
  },
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,OPTIONS,PATCH,DELETE,POST,PUT' },
          { key: 'Access-Control-Allow-Headers', value: 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version' },
        ],
      },
    ];
  },
  async redirects() {
    return [
      {
        source: '/admin',
        destination: process.env.NEXT_PUBLIC_ADMIN_URL || '/admin/login',
        permanent: false,
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.NEXT_PUBLIC_API_URL}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
```

#### 2. App Layout Structure
```typescript
// apps/web/app/layout.tsx
import { Inter } from 'next/font/google';
import { Metadata } from 'next';
import { Providers } from '@/components/providers';
import { Header } from '@/components/layout/header';
import { Footer } from '@/components/layout/footer';
import { Toaster } from '@/components/ui/toaster';
import { Analytics } from '@/components/analytics';
import './globals.css';

const inter = Inter({ 
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-inter',
});

export const metadata: Metadata = {
  title: {
    default: 'Nutrition Platform - Transform Your Health Naturally',
    template: '%s | Nutrition Platform',
  },
  description: 'Personalized functional nutrition and evidence-based lifestyle coaching to help you reverse chronic symptoms and thrive.',
  keywords: ['nutrition', 'functional medicine', 'gut health', 'wellness', 'health coaching'],
  authors: [{ name: 'Nutrition Platform' }],
  creator: 'Nutrition Platform',
  publisher: 'Nutrition Platform',
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || 'https://nutritionplatform.com'),
  openGraph: {
    title: 'Nutrition Platform - Transform Your Health Naturally',
    description: 'Personalized functional nutrition and evidence-based lifestyle coaching',
    url: '/',
    siteName: 'Nutrition Platform',
    images: [
      {
        url: '/og-image.jpg',
        width: 1200,
        height: 630,
        alt: 'Nutrition Platform',
      },
    ],
    locale: 'en_IN',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Nutrition Platform - Transform Your Health Naturally',
    description: 'Personalized functional nutrition and evidence-based lifestyle coaching',
    images: ['/twitter-image.jpg'],
    creator: '@nutritionplatform',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  verification: {
    google: process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION,
    yandex: process.env.NEXT_PUBLIC_YANDEX_VERIFICATION,
    yahoo: process.env.NEXT_PUBLIC_YAHOO_VERIFICATION,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="min-h-screen bg-background font-sans antialiased">
        <Providers>
          <div className="relative flex min-h-screen flex-col">
            <Header />
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
          <Toaster />
          <Analytics />
        </Providers>
      </body>
    </html>
  );
}
```

#### 3. Providers Setup
```typescript
// apps/web/components/providers.tsx
'use client';

import { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { SessionProvider } from 'next-auth/react';
import { ThemeProvider } from 'next-themes';
import { AuthProvider } from '@/contexts/auth-context';
import { NotificationProvider } from '@/contexts/notification-context';
import { ModalProvider } from '@/contexts/modal-context';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      gcTime: 10 * 60 * 1000, // 10 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export function Providers({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider
          attribute="class"
          defaultTheme="light"
          enableSystem
          disableTransitionOnChange
        >
          <AuthProvider>
            <NotificationProvider>
              <ModalProvider>
                {children}
              </ModalProvider>
            </NotificationProvider>
          </AuthProvider>
        </ThemeProvider>
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </SessionProvider>
  );
}
```

### Day 4-5: Authentication Implementation

#### 1. Auth Context
```typescript
// apps/web/contexts/auth-context.tsx
'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useSession } from 'next-auth/react';
import { api } from '@/lib/api';
import { User } from '@/types/user';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  updateProfile: (data: Partial<User>) => Promise<void>;
  verifyEmail: (token: string) => Promise<void>;
  resendVerification: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({} as AuthContextType);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { data: session, status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === 'loading') return;
    
    if (session?.user) {
      fetchUserProfile();
    } else {
      setIsLoading(false);
    }
  }, [session, status]);

  const fetchUserProfile = async () => {
    try {
      const { data } = await api.get('/users/profile');
      setUser(data);
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    try {
      const { data } = await api.post('/auth/login', { email, password });
      
      // Store tokens
      localStorage.setItem('accessToken', data.tokens.accessToken);
      localStorage.setItem('refreshToken', data.tokens.refreshToken);
      
      setUser(data.user);
      
      // Redirect based on role
      if (data.user.role === 'ADMIN') {
        router.push('/admin');
      } else if (data.user.role === 'NUTRITIONIST') {
        router.push('/nutritionist/dashboard');
      } else {
        router.push('/dashboard');
      }
    } catch (error) {
      throw error;
    }
  };

  const register = async (data: RegisterData) => {
    try {
      const response = await api.post('/auth/register', data);
      
      // Auto-login after registration
      await login(data.email, data.password);
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      setUser(null);
      router.push('/');
    }
  };

  const updateProfile = async (data: Partial<User>) => {
    try {
      const response = await api.put('/users/profile', data);
      setUser(response.data);
    } catch (error) {
      throw error;
    }
  };

  const verifyEmail = async (token: string) => {
    try {
      await api.post('/auth/verify-email', { token });
      
      // Refresh user data
      await fetchUserProfile();
    } catch (error) {
      throw error;
    }
  };

  const resendVerification = async () => {
    try {
      await api.post('/auth/resend-verification');
    } catch (error) {
      throw error;
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        updateProfile,
        verifyEmail,
        resendVerification,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

#### 2. Login Page
```typescript
// apps/web/app/(auth)/login/page.tsx
'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuth } from '@/contexts/auth-context';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Icons } from '@/components/icons';
import { toast } from '@/components/ui/use-toast';

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  rememberMe: z.boolean().optional(),
});

type LoginFormData = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [twoFactorRequired, setTwoFactorRequired] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const router = useRouter();
  const { login } = useAuth();

  const {
    register,
    handleSubmit,
    formState: { errors },
    setError,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: LoginFormData) => {
    setIsLoading(true);

    try {
      await login(data.email, data.password);
      
      toast({
        title: 'Welcome back!',
        description: 'You have successfully logged in.',
      });
    } catch (error: any) {
      if (error.response?.data?.requiresTwoFactor) {
        setTwoFactorRequired(true);
      } else {
        setError('root', {
          message: error.response?.data?.message || 'Invalid email or password',
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleTwoFactorSubmit = async () => {
    setIsLoading(true);

    try {
      // Submit with 2FA code
      const data = new FormData(document.getElementById('login-form') as HTMLFormElement);
      await login(
        data.get('email') as string,
        data.get('password') as string,
        twoFactorCode
      );
    } catch (error: any) {
      toast({
        title: 'Invalid code',
        description: 'Please check your authenticator app and try again.',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="container relative min-h-screen flex-col items-center justify-center md:grid lg:max-w-none lg:grid-cols-2 lg:px-0">
      <div className="relative hidden h-full flex-col bg-muted p-10 text-white dark:border-r lg:flex">
        <div className="absolute inset-0 bg-gradient-to-br from-green-600 to-green-800" />
        <div className="relative z-20 flex items-center text-lg font-medium">
          <Icons.logo className="mr-2 h-6 w-6" />
          Nutrition Platform
        </div>
        <div className="relative z-20 mt-auto">
          <blockquote className="space-y-2">
            <p className="text-lg">
              "This platform has completely transformed my approach to health. The personalized guidance and support have been life-changing."
            </p>
            <footer className="text-sm">Sarah Johnson</footer>
          </blockquote>
        </div>
      </div>
      <div className="lg:p-8">
        <div className="mx-auto flex w-full flex-col justify-center space-y-6 sm:w-[350px]">
          <div className="flex flex-col space-y-2 text-center">
            <h1 className="text-2xl font-semibold tracking-tight">
              Welcome back
            </h1>
            <p className="text-sm text-muted-foreground">
              Enter your email to sign in to your account
            </p>
          </div>

          <Card>
            <form id="login-form" onSubmit={handleSubmit(onSubmit)}>
              <CardHeader className="space-y-1">
                <CardTitle className="text-2xl">Sign in</CardTitle>
                <CardDescription>
                  Enter your email and password to access your account
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4">
                {errors.root && (
                  <Alert variant="destructive">
                    <AlertDescription>{errors.root.message}</AlertDescription>
                  </Alert>
                )}

                {!twoFactorRequired ? (
                  <>
                    <div className="grid gap-2">
                      <Label htmlFor="email">Email</Label>
                      <Input
                        {...register('email')}
                        id="email"
                        type="email"
                        placeholder="name@example.com"
                        autoCapitalize="none"
                        autoComplete="email"
                        autoCorrect="off"
                        disabled={isLoading}
                      />
                      {errors.email && (
                        <p className="text-sm text-red-500">{errors.email.message}</p>
                      )}
                    </div>
                    <div className="grid gap-2">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="password">Password</Label>
                        <Link
                          href="/forgot-password"
                          className="text-sm text-primary hover:underline"
                        >
                          Forgot password?
                        </Link>
                      </div>
                      <div className="relative">
                        <Input
                          {...register('password')}
                          id="password"
                          type={showPassword ? 'text' : 'password'}
                          disabled={isLoading}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-3 top-3 text-gray-500"
                        >
                          {showPassword ? (
                            <Icons.eyeOff className="h-4 w-4" />
                          ) : (
                            <Icons.eye className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                      {errors.password && (
                        <p className="text-sm text-red-500">{errors.password.message}</p>
                      )}
                    </div>
                    <div className="flex items-center space-x-2">
                      <input
                        {...register('rememberMe')}
                        type="checkbox"
                        id="remember"
                        className="rounded border-gray-300"
                      />
                      <Label
                        htmlFor="remember"
                        className="text-sm font-normal cursor-pointer"
                      >
                        Remember me
                      </Label>
                    </div>
                  </>
                ) : (
                  <div className="grid gap-2">
                    <Label htmlFor="twoFactorCode">Two-Factor Code</Label>
                    <Input
                      id="twoFactorCode"
                      type="text"
                      placeholder="000000"
                      value={twoFactorCode}
                      onChange={(e) => setTwoFactorCode(e.target.value)}
                      maxLength={6}
                      autoComplete="one-time-code"
                      disabled={isLoading}
                    />
                    <p className="text-sm text-muted-foreground">
                      Enter the 6-digit code from your authenticator app
                    </p>
                  </div>
                )}
              </CardContent>
              <CardFooter className="flex flex-col gap-4">
                {!twoFactorRequired ? (
                  <Button
                    type="submit"
                    className="w-full"
                    disabled={isLoading}
                  >
                    {isLoading && (
                      <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Sign In
                  </Button>
                ) : (
                  <Button
                    type="button"
                    onClick={handleTwoFactorSubmit}
                    className="w-full"
                    disabled={isLoading}
                  >
                    {isLoading && (
                      <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Verify Code
                  </Button>
                )}

                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-background px-2 text-muted-foreground">
                      Or continue with
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <Button variant="outline" type="button" disabled={isLoading}>
                    <Icons.google className="mr-2 h-4 w-4" />
                    Google
                  </Button>
                  <Button variant="outline" type="button" disabled={isLoading}>
                    <Icons.facebook className="mr-2 h-4 w-4" />
                    Facebook
                  </Button>
                </div>

                <p className="text-center text-sm text-muted-foreground">
                  Don't have an account?{' '}
                  <Link
                    href="/register"
                    className="underline underline-offset-4 hover:text-primary"
                  >
                    Sign up
                  </Link>
                </p>
              </CardFooter>
            </form>
          </Card>
        </div>
      </div>
    </div>
  );
}
```

### Day 6-7: Homepage Implementation

#### 1. Homepage Component
```typescript
// apps/web/app/page.tsx
import { Metadata } from 'next';
import { HeroSection } from '@/components/home/hero-section';
import { FeaturesSection } from '@/components/home/features-section';
import { ProgramsSection } from '@/components/home/programs-section';
import { TestimonialsSection } from '@/components/home/testimonials-section';
import { CTASection } from '@/components/home/cta-section';
import { BlogSection } from '@/components/home/blog-section';
import { FAQSection } from '@/components/home/faq-section';

export const metadata: Metadata = {
  title: 'Transform Your Health Naturally - Personalized Nutrition Coaching',
  description: 'Evidence-based functional nutrition programs to heal your gut, balance hormones, and reclaim your energy. Book your free discovery call today.',
};

export default async function HomePage() {
  return (
    <>
      <HeroSection />
      <FeaturesSection />
      <ProgramsSection />
      <TestimonialsSection />
      <CTASection />
      <BlogSection />
      <FAQSection />
    </>
  );
}
```

#### 2. Hero Section
```typescript
// apps/web/components/home/hero-section.tsx
'use client';

import { useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Icons } from '@/components/icons';
import { QuizModal } from '@/components/modals/quiz-modal';

export function HeroSection() {
  const [showQuizModal, setShowQuizModal] = useState(false);

  return (
    <section className="relative overflow-hidden bg-gradient-to-b from-green-50 to-white dark:from-green-950 dark:to-background">
      <div className="absolute inset-0 bg-grid-slate-100 [mask-image:radial-gradient(ellipse_at_center,white,transparent)] dark:bg-grid-slate-700/25" />
      
      <div className="container relative z-10 px-4 py-24 sm:px-6 sm:py-32 lg:px-8">
        <div className="grid gap-12 lg:grid-cols-2 lg:gap-8 items-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mx-auto max-w-2xl lg:mx-0"
          >
            <Badge className="mb-4" variant="secondary">
              🌱 Transform Your Health Naturally
            </Badge>
            
            <h1 className="text-4xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-6xl">
              Restore Your Balance.{' '}
              <span className="text-green-600 dark:text-green-400">
                Naturally.
              </span>
            </h1>
            
            <p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
              Personalized functional nutrition and evidence-based lifestyle coaching 
              to help you reverse chronic symptoms and thrive. Heal your gut, 
              balance your hormones, and reclaim your energy.
            </p>
            
            <div className="mt-10 flex items-center gap-x-6">
              <Button
                size="lg"
                className="bg-green-600 hover:bg-green-700"
                asChild
              >
                <Link href="/book-consultation">
                  Book Free Discovery Call
                  <Icons.arrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              
              <Button
                variant="outline"
                size="lg"
                onClick={() => setShowQuizModal(true)}
              >
                <Icons.clipboard className="mr-2 h-4 w-4" />
                Take Health Quiz
              </Button>
            </div>
            
            <div className="mt-10 grid grid-cols-3 gap-8 border-t border-gray-200 dark:border-gray-800 pt-10">
              <div>
                <p className="text-3xl font-bold text-green-600 dark:text-green-400">
                  500+
                </p>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                  Clients Transformed
                </p>
              </div>
              <div>
                <p className="text-3xl font-bold text-green-600 dark:text-green-400">
                  95%
                </p>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                  Success Rate
                </p>
              </div>
              <div>
                <p className="text-3xl font-bold text-green-600 dark:text-green-400">
                  4.9
                </p>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                  Average Rating
                </p>
              </div>
            </div>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="relative mx-auto w-full max-w-lg lg:mx-0"
          >
            <div className="relative aspect-[3/4] overflow-hidden rounded-2xl bg-gray-100 dark:bg-gray-800">
              <Image
                src="/images/hero-nutritionist.jpg"
                alt="Nutritionist consultation"
                fill
                className="object-cover"
                priority
              />
              
              {/* Floating cards */}
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: 0.5 }}
                className="absolute left-4 top-4 rounded-lg bg-white/90 dark:bg-gray-900/90 p-4 shadow-lg backdrop-blur-sm"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900">
                    <Icons.heart className="h-6 w-6 text-green-600 dark:text-green-400" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold">Gut Health</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">
                      Specialized Program
                    </p>
                  </div>
                </div>
              </motion.div>
              
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: 0.7 }}
                className="absolute bottom-4 right-4 rounded-lg bg-white/90 dark:bg-gray-900/90 p-4 shadow-lg backdrop-blur-sm"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900">
                    <Icons.calendar className="h-6 w-6 text-purple-600 dark:text-purple-400" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold">Next Available</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">
                      Tomorrow, 10 AM
                    </p>
                  </div>
                </div>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>
      
      <QuizModal
        isOpen={showQuizModal}
        onClose={() => setShowQuizModal(false)}
      />
    </section>
  );
}
```

#### 3. Programs Section
```typescript
// apps/web/components/home/programs-section.tsx
'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Icons } from '@/components/icons';
import { api } from '@/lib/api';

interface Program {
  id: string;
  name: string;
  slug: string;
  shortDescription: string;
  duration: number;
  price: number;
  features: string[];
  type: string;
}

export function ProgramsSection() {
  const { data, isLoading } = useQuery({
    queryKey: ['featured-programs'],
    queryFn: async () => {
      const response = await api.get('/programs?featured=true&limit=3');
      return response.data.programs;
    },
  });

  const programIcons = {
    GUT_HEALTH: Icons.stomach,
    METABOLIC_RESET: Icons.flame,
    PCOS_RESTORE: Icons.flower,
    DIABETES_CARE: Icons.heart,
  };

  return (
    <section className="py-24 bg-gray-50 dark:bg-gray-900/50">
      <div className="container px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <h2 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-4xl">
            Transform Your Health With Our Programs
          </h2>
          <p className="mt-4 text-lg text-gray-600 dark:text-gray-300">
            Evidence-based programs designed to address the root cause of your symptoms
          </p>
        </div>

        <div className="mt-16 grid gap-8 md:grid-cols-2 lg:grid-cols-3">
          {isLoading ? (
            // Loading skeleton
            Array.from({ length: 3 }).map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader>
                  <div className="h-12 w-12 bg-gray-200 dark:bg-gray-700 rounded-full mb-4" />
                  <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
                  <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-full mt-2" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Array.from({ length: 4 }).map((_, j) => (
                      <div key={j} className="h-4 bg-gray-200 dark:bg-gray-700 rounded" />
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))
          ) : (
            data?.map((program: Program, index: number) => {
              const Icon = programIcons[program.type as keyof typeof programIcons] || Icons.heart;
              
              return (
                <motion.div
                  key={program.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                >
                  <Card className="relative h-full hover:shadow-lg transition-shadow">
                    <CardHeader>
                      <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900">
                        <Icon className="h-6 w-6 text-green-600 dark:text-green-400" />
                      </div>
                      <CardTitle>{program.name}</CardTitle>
                      <CardDescription>{program.shortDescription}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="mb-4 flex items-center justify-between">
                        <Badge variant="secondary">
                          {program.duration} week program
                        </Badge>
                        <p className="text-2xl font-bold">
                          ₹{program.price.toLocaleString()}
                        </p>
                      </div>
                      <ul className="space-y-2">
                        {program.features.slice(0, 4).map((feature, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <Icons.check className="h-4 w-4 text-green-600 dark:text-green-400 mt-0.5" />
                            <span className="text-sm text-gray-600 dark:text-gray-300">
                              {feature}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                    <CardFooter>
                      <Button className="w-full" asChild>
                        <Link href={`/programs/${program.slug}`}>
                          Learn More
                          <Icons.arrowRight className="ml-2 h-4 w-4" />
                        </Link>
                      </Button>
                    </CardFooter>
                  </Card>
                </motion.div>
              );
            })
          )}
        </div>

        <div className="mt-12 text-center">
          <Button variant="outline" size="lg" asChild>
            <Link href="/programs">
              View All Programs
              <Icons.arrowRight className="ml-2 h-4 w-4" />
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
}
```

## Week 10: Dashboard & User Features

### Day 1-3: User Dashboard

#### 1. Dashboard Layout
```typescript
// apps/web/app/(dashboard)/dashboard/layout.tsx
import { redirect } from 'next/navigation';
import { getServerSession } from 'next-auth';
import { DashboardNav } from '@/components/dashboard/nav';
import { DashboardHeader } from '@/components/dashboard/header';
import { authOptions } from '@/lib/auth';

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession(authOptions);

  if (!session) {
    redirect('/login');
  }

  return (
    <div className="flex min-h-screen flex-col">
      <DashboardHeader user={session.user} />
      <div className="container flex-1 items-start md:grid md:grid-cols-[220px_minmax(0,1fr)] md:gap-6 lg:grid-cols-[240px_minmax(0,1fr)] lg:gap-10">
        <aside className="fixed top-14 z-30 -ml-2 hidden h-[calc(100vh-3.5rem)] w-full shrink-0 overflow-y-auto border-r md:sticky md:block">
          <DashboardNav />
        </aside>
        <main className="flex w-full flex-col overflow-hidden py-6">
          {children}
        </main>
      </div>
    </div>
  );
}
```

#### 2. Dashboard Overview
```typescript
// apps/web/app/(dashboard)/dashboard/page.tsx
'use client';

import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { Icons } from '@/components/icons';
import { HealthMetricsChart } from '@/components/dashboard/health-metrics-chart';
import { UpcomingConsultations } from '@/components/dashboard/upcoming-consultations';
import { RecentActivity } from '@/components/dashboard/recent-activity';
import { QuickActions } from '@/components/dashboard/quick-actions';
import { api } from '@/lib/api';

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const response = await api.get('/users/dashboard-stats');
      return response.data;
    },
  });

  const { data: journey, isLoading: journeyLoading } = useQuery({
    queryKey: ['current-journey'],
    queryFn: async () => {
      const response = await api.get('/journeys/current');
      return response.data;
    },
  });

  return (
    <div className="space-y-8">
      {/* Welcome Section */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          Welcome back, {stats?.user?.firstName}!
        </h1>
        <p className="text-muted-foreground">
          Here's an overview of your health journey
        </p>
      </div>

      {/* Quick Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Current Program
            </CardTitle>
            <Icons.book className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {journey?.program?.name || 'None'}
            </div>
            {journey && (
              <div className="mt-2">
                <Progress value={journey.progress.percentage} className="h-2" />
                <p className="text-xs text-muted-foreground mt-1">
                  {journey.progress.percentage}% complete
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Next Consultation
            </CardTitle>
            <Icons.calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.nextConsultation ? (
                new Date(stats.nextConsultation.scheduledAt).toLocaleDateString()
              ) : (
                'None scheduled'
              )}
            </div>
            {stats?.nextConsultation && (
              <p className="text-xs text-muted-foreground">
                with {stats.nextConsultation.nutritionist.name}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Health Score
            </CardTitle>
            <Icons.heart className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.healthScore || 0}/100</div>
            <p className="text-xs text-muted-foreground">
              {stats?.healthScoreChange > 0 ? '+' : ''}{stats?.healthScoreChange || 0} from last week
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Days Tracked
            </CardTitle>
            <Icons.checkCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.trackedDays || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.currentStreak || 0} day streak
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <QuickActions />

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="metrics">Health Metrics</TabsTrigger>
          <TabsTrigger value="consultations">Consultations</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
            <Card className="col-span-4">
              <CardHeader>
                <CardTitle>Health Metrics</CardTitle>
                <CardDescription>
                  Your key health indicators over the past 30 days
                </CardDescription>
              </CardHeader>
              <CardContent className="pl-2">
                <HealthMetricsChart />
              </CardContent>
            </Card>

            <Card className="col-span-3">
              <CardHeader>
                <CardTitle>Today's Summary</CardTitle>
                <CardDescription>
                  Your progress for {new Date().toLocaleDateString()}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Water Intake</span>
                      <span className="text-sm text-muted-foreground">
                        {journey?.todayNutrition?.water || 0}/8 glasses
                      </span>
                    </div>
                    <Progress
                      value={(journey?.todayNutrition?.water || 0) * 12.5}
                      className="h-2"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Calories</span>
                      <span className="text-sm text-muted-foreground">
                        {journey?.todayNutrition?.calories || 0}/2000 kcal
                      </span>
                    </div>
                    <Progress
                      value={(journey?.todayNutrition?.calories || 0) / 20}
                      className="h-2"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Exercise</span>
                      <span className="text-sm text-muted-foreground">
                        {journey?.todayActivity?.exercise || 0}/30 min
                      </span>
                    </div>
                    <Progress
                      value={(journey?.todayActivity?.exercise || 0) * 3.33}
                      className="h-2"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Sleep</span>
                      <span className="text-sm text-muted-foreground">
                        {journey?.todayActivity?.sleep || 0}/8 hours
                      </span>
                    </div>
                    <Progress
                      value={(journey?.todayActivity?.sleep || 0) * 12.5}
                      className="h-2"
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="metrics">
          <HealthMetricsChart detailed />
        </TabsContent>

        <TabsContent value="consultations">
          <UpcomingConsultations />
        </TabsContent>

        <TabsContent value="activity">
          <RecentActivity />
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

### Day 4-5: Health Journey Tracking

#### 1. Journey Tracker
```typescript
// apps/web/app/(dashboard)/dashboard/journey/page.tsx
'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Calendar } from '@/components/ui/calendar';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Icons } from '@/components/icons';
import { toast } from '@/components/ui/use-toast';
import { MealTracker } from '@/components/journey/meal-tracker';
import { SymptomTracker } from '@/components/journey/symptom-tracker';
import { ProgressChart } from '@/components/journey/progress-chart';
import { api } from '@/lib/api';

export default function JourneyPage() {
  const [selectedDate, setSelectedDate] = useState<Date>(new Date());
  const [checkInDialogOpen, setCheckInDialogOpen] = useState(false);
  const queryClient = useQueryClient();

  const { data: journey } = useQuery({
    queryKey: ['journey'],
    queryFn: async () => {
      const response = await api.get('/journeys/current');
      return response.data;
    },
  });

  const { data: checkIns } = useQuery({
    queryKey: ['check-ins', journey?.id],
    queryFn: async () => {
      if (!journey?.id) return [];
      const response = await api.get(`/journeys/${journey.id}/check-ins`);
      return response.data;
    },
    enabled: !!journey?.id,
  });

  const createCheckIn = useMutation({
    mutationFn: async (data: any) => {
      const response = await api.post('/journeys/check-ins', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['check-ins'] });
      queryClient.invalidateQueries({ queryKey: ['journey'] });
      setCheckInDialogOpen(false);
      toast({
        title: 'Check-in recorded',
        description: 'Great job tracking your progress!',
      });
    },
  });

  const handleCheckInSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    
    createCheckIn.mutate({
      date: selectedDate,
      weight: parseFloat(formData.get('weight') as string),
      energy: parseInt(formData.get('energy') as string),
      mood: parseInt(formData.get('mood') as string),
      sleep: parseFloat(formData.get('sleep') as string),
      exercise: parseInt(formData.get('exercise') as string),
      water: parseInt(formData.get('water') as string),
      symptoms: formData.get('symptoms')?.toString().split(',').filter(Boolean) || [],
      notes: formData.get('notes') as string,
    });
  };

  if (!journey) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <Icons.clipboard className="h-12 w-12 text-muted-foreground mb-4" />
        <h2 className="text-xl font-semibold mb-2">No Active Journey</h2>
        <p className="text-muted-foreground mb-4">
          Start a program to begin tracking your health journey
        </p>
        <Button asChild>
          <Link href="/programs">Browse Programs</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Health Journey</h1>
        <p className="text-muted-foreground">
          Track your progress in the {journey.program.name} program
        </p>
      </div>

      {/* Progress Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Program Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{journey.progress.percentage}%</div>
            <Progress value={journey.progress.percentage} className="mt-2 h-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Days Completed</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{journey.progress.elapsedDays}</div>
            <p className="text-xs text-muted-foreground">
              of {journey.program.duration} days
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Check-ins</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{checkIns?.length || 0}</div>
            <p className="text-xs text-muted-foreground">Total recorded</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Current Streak</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{journey.currentStreak || 0}</div>
            <p className="text-xs text-muted-foreground">days</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="today" className="space-y-4">
        <TabsList>
          <TabsTrigger value="today">Today</TabsTrigger>
          <TabsTrigger value="progress">Progress</TabsTrigger>
          <TabsTrigger value="calendar">Calendar</TabsTrigger>
          <TabsTrigger value="insights">Insights</TabsTrigger>
        </TabsList>

        <TabsContent value="today" className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">
              {format(selectedDate, 'EEEE, MMMM d, yyyy')}
            </h2>
            <Dialog open={checkInDialogOpen} onOpenChange={setCheckInDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Icons.plus className="mr-2 h-4 w-4" />
                  Daily Check-in
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Daily Check-in</DialogTitle>
                  <DialogDescription>
                    Record your daily health metrics and how you're feeling
                  </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleCheckInSubmit} className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="weight">Weight (kg)</Label>
                      <Input
                        id="weight"
                        name="weight"
                        type="number"
                        step="0.1"
                        placeholder="70.5"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="sleep">Sleep (hours)</Label>
                      <Input
                        id="sleep"
                        name="sleep"
                        type="number"
                        step="0.5"
                        min="0"
                        max="24"
                        placeholder="8"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="energy">Energy Level</Label>
                      <Select name="energy">
                        <SelectTrigger>
                          <SelectValue placeholder="Select energy level" />
                        </SelectTrigger>
                        <SelectContent>
                          {Array.from({ length: 10 }, (_, i) => i + 1).map((level) => (
                            <SelectItem key={level} value={level.toString()}>
                              {level} - {level <= 3 ? 'Low' : level <= 7 ? 'Moderate' : 'High'}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="mood">Mood</Label>
                      <Select name="mood">
                        <SelectTrigger>
                          <SelectValue placeholder="Select mood" />
                        </SelectTrigger>
                        <SelectContent>
                          {Array.from({ length: 10 }, (_, i) => i + 1).map((level) => (
                            <SelectItem key={level} value={level.toString()}>
                              {level} - {level <= 3 ? 'Poor' : level <= 7 ? 'Good' : 'Excellent'}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="exercise">Exercise (minutes)</Label>
                      <Input
                        id="exercise"
                        name="exercise"
                        type="number"
                        min="0"
                        placeholder="30"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="water">Water (glasses)</Label>
                      <Input
                        id="water"
                        name="water"
                        type="number"
                        min="0"
                        placeholder="8"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="symptoms">Symptoms (comma-separated)</Label>
                    <Input
                      id="symptoms"
                      name="symptoms"
                      placeholder="bloating, fatigue, headache"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="notes">Notes</Label>
                    <Textarea
                      id="notes"
                      name="notes"
                      placeholder="How are you feeling today? Any observations?"
                      rows={3}
                    />
                  </div>

                  <div className="flex justify-end gap-4">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setCheckInDialogOpen(false)}
                    >
                      Cancel
                    </Button>
                    <Button type="submit" disabled={createCheckIn.isPending}>
                      {createCheckIn.isPending && (
                        <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                      )}
                      Save Check-in
                    </Button>
                  </div>
                </form>
              </DialogContent>
            </Dialog>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <MealTracker date={selectedDate} />
            <SymptomTracker date={selectedDate} />
          </div>
        </TabsContent>

        <TabsContent value="progress">
          <ProgressChart journeyId={journey.id} />
        </TabsContent>

        <TabsContent value="calendar">
          <Card>
            <CardHeader>
              <CardTitle>Journey Calendar</CardTitle>
              <CardDescription>
                View your check-ins and track your consistency
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Calendar
                mode="single"
                selected={selectedDate}
                onSelect={(date) => date && setSelectedDate(date)}
                modifiers={{
                  checkIn: checkIns?.map((c: any) => new Date(c.date)) || [],
                }}
                modifiersStyles={{
                  checkIn: {
                    backgroundColor: 'rgb(34 197 94)',
                    color: 'white',
                    borderRadius: '50%',
                  },
                }}
                className="rounded-md border"
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="insights">
          <div className="grid gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Your Progress Insights</CardTitle>
                <CardDescription>
                  AI-powered analysis of your health journey
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {/* Insights would be generated based on check-in data */}
                  <div className="flex gap-4 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                    <Icons.trendingUp className="h-5 w-5 text-green-600 dark:text-green-400 mt-0.5" />
                    <div>
                      <p className="font-medium">Great Progress!</p>
                      <p className="text-sm text-muted-foreground">
                        Your energy levels have improved by 30% over the past week.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <Icons.lightbulb className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5" />
                    <div>
                      <p className="font-medium">Sleep Pattern</p>
                      <p className="text-sm text-muted-foreground">
                        You tend to have better energy on days with 7+ hours of sleep.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4 p-4 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
                    <Icons.alertCircle className="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5" />
                    <div>
                      <p className="font-medium">Hydration Reminder</p>
                      <p className="text-sm text-muted-foreground">
                        Your water intake has been below target for 3 days. Try to reach 8 glasses daily.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

### Day 6-7: Consultation Booking

#### 1. Consultation Booking Page
```typescript
// apps/web/app/(dashboard)/dashboard/consultations/book/page.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery, useMutation } from '@tanstack/react-query';
import { format, addDays } from 'date-fns';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Calendar } from '@/components/ui/calendar';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Textarea } from '@/components/ui/textarea';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Icons } from '@/components/icons';
import { toast } from '@/components/ui/use-toast';
import { api } from '@/lib/api';

export default function BookConsultationPage() {
  const router = useRouter();
  const [selectedNutritionist, setSelectedNutritionist] = useState<string>('');
  const [selectedDate, setSelectedDate] = useState<Date | undefined>();
  const [selectedSlot, setSelectedSlot] = useState<string>('');
  const [notes, setNotes] = useState('');

  const { data: nutritionists, isLoading: nutritionistsLoading } = useQuery({
    queryKey: ['nutritionists'],
    queryFn: async () => {
      const response = await api.get('/nutritionists');
      return response.data;
    },
  });

  const { data: slots, isLoading: slotsLoading } = useQuery({
    queryKey: ['available-slots', selectedNutritionist, selectedDate],
    queryFn: async () => {
      if (!selectedNutritionist || !selectedDate) return [];
      
      const response = await api.get('/consultations/available-slots', {
        params: {
          nutritionistId: selectedNutritionist,
          date: format(selectedDate, 'yyyy-MM-dd'),
        },
      });
      return response.data;
    },
    enabled: !!selectedNutritionist && !!selectedDate,
  });

  const bookConsultation = useMutation({
    mutationFn: async (data: any) => {
      const response = await api.post('/consultations/book', data);
      return response.data;
    },
    onSuccess: (data) => {
      toast({
        title: 'Consultation booked!',
        description: 'You will receive a confirmation email shortly.',
      });
      router.push(`/dashboard/consultations/${data.id}`);
    },
    onError: (error: any) => {
      toast({
        title: 'Booking failed',
        description: error.response?.data?.message || 'Please try again later.',
        variant: 'destructive',
      });
    },
  });

  const handleBooking = () => {
    if (!selectedNutritionist || !selectedDate || !selectedSlot) {
      toast({
        title: 'Missing information',
        description: 'Please select a nutritionist, date, and time slot.',
        variant: 'destructive',
      });
      return;
    }

    bookConsultation.mutate({
      nutritionistId: selectedNutritionist,
      scheduledAt: selectedSlot,
      duration: 60,
      notes,
    });
  };

  const disabledDays = {
    before: new Date(),
    after: addDays(new Date(), 30),
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Book a Consultation</h1>
        <p className="text-muted-foreground">
          Schedule a one-on-one session with our expert nutritionists
        </p>
      </div>

      {/* Step 1: Select Nutritionist */}
      <Card>
        <CardHeader>
          <CardTitle>1. Choose Your Nutritionist</CardTitle>
          <CardDescription>
            Select a nutritionist based on their specialization and availability
          </CardDescription>
        </CardHeader>
        <CardContent>
          {nutritionistsLoading ? (
            <div className="flex justify-center py-8">
              <Icons.spinner className="h-8 w-8 animate-spin" />
            </div>
          ) : (
            <RadioGroup
              value={selectedNutritionist}
              onValueChange={setSelectedNutritionist}
            >
              <div className="grid gap-4">
                {nutritionists?.map((nutritionist: any) => (
                  <label
                    key={nutritionist.id}
                    htmlFor={nutritionist.id}
                    className={`flex items-start gap-4 p-4 rounded-lg border cursor-pointer transition-colors ${
                      selectedNutritionist === nutritionist.id
                        ? 'border-primary bg-primary/5'
                        : 'border-gray-200 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-900'
                    }`}
                  >
                    <RadioGroupItem
                      value={nutritionist.id}
                      id={nutritionist.id}
                      className="mt-1"
                    />
                    <Avatar className="h-12 w-12">
                      <AvatarImage src={nutritionist.avatar} />
                      <AvatarFallback>
                        {nutritionist.name.split(' ').map((n: string) => n[0]).join('')}
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1">
                      <div className="flex items-start justify-between">
                        <div>
                          <h3 className="font-semibold">{nutritionist.name}</h3>
                          <p className="text-sm text-muted-foreground">
                            {nutritionist.qualifications}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="font-semibold">₹{nutritionist.consultationFee}</p>
                          <p className="text-sm text-muted-foreground">per session</p>
                        </div>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {nutritionist.specializations.map((spec: string) => (
                          <Badge key={spec} variant="secondary">
                            {spec}
                          </Badge>
                        ))}
                      </div>
                      <div className="mt-2 flex items-center gap-4 text-sm">
                        <div className="flex items-center gap-1">
                          <Icons.star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                          <span>{nutritionist.rating}</span>
                          <span className="text-muted-foreground">
                            ({nutritionist.totalReviews} reviews)
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Icons.globe className="h-4 w-4" />
                          <span>{nutritionist.languages.join(', ')}</span>
                        </div>
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </RadioGroup>
          )}
        </CardContent>
      </Card>

      {/* Step 2: Select Date */}
      {selectedNutritionist && (
        <Card>
          <CardHeader>
            <CardTitle>2. Select Date</CardTitle>
            <CardDescription>
              Choose your preferred consultation date
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Calendar
              mode="single"
              selected={selectedDate}
              onSelect={setSelectedDate}
              disabled={disabledDays}
              className="rounded-md border"
            />
          </CardContent>
        </Card>
      )}

      {/* Step 3: Select Time Slot */}
      {selectedDate && (
        <Card>
          <CardHeader>
            <CardTitle>3. Select Time Slot</CardTitle>
            <CardDescription>
              Available time slots for {format(selectedDate, 'EEEE, MMMM d, yyyy')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {slotsLoading ? (
              <div className="flex justify-center py-8">
                <Icons.spinner className="h-8 w-8 animate-spin" />
              </div>
            ) : slots?.length === 0 ? (
              <p className="text-center py-8 text-muted-foreground">
                No available slots for this date. Please select another date.
              </p>
            ) : (
              <RadioGroup value={selectedSlot} onValueChange={setSelectedSlot}>
                <div className="grid grid-cols-3 gap-3 sm:grid-cols-4 md:grid-cols-6">
                  {slots?.map((slot: any) => (
                    <label
                      key={slot.time}
                      htmlFor={slot.time}
                      className={`flex items-center justify-center p-3 rounded-md border cursor-pointer transition-colors ${
                        !slot.available
                          ? 'opacity-50 cursor-not-allowed'
                          : selectedSlot === slot.time
                          ? 'border-primary bg-primary text-primary-foreground'
                          : 'border-gray-200 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-900'
                      }`}
                    >
                      <RadioGroupItem
                        value={slot.time}
                        id={slot.time}
                        disabled={!slot.available}
                        className="sr-only"
                      />
                      {format(new Date(slot.time), 'h:mm a')}
                    </label>
                  ))}
                </div>
              </RadioGroup>
            )}
          </CardContent>
        </Card>
      )}

      {/* Step 4: Additional Notes */}
      {selectedSlot && (
        <Card>
          <CardHeader>
            <CardTitle>4. Additional Information (Optional)</CardTitle>
            <CardDescription>
              Share any specific concerns or topics you'd like to discuss
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              placeholder="E.g., I've been experiencing digestive issues after meals..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={4}
            />
          </CardContent>
        </Card>
      )}

      {/* Booking Summary */}
      {selectedNutritionist && selectedDate && selectedSlot && (
        <Card>
          <CardHeader>
            <CardTitle>Booking Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Nutritionist:</dt>
                <dd className="font-medium">
                  {nutritionists?.find((n: any) => n.id === selectedNutritionist)?.name}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Date:</dt>
                <dd className="font-medium">
                  {format(selectedDate, 'EEEE, MMMM d, yyyy')}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Time:</dt>
                <dd className="font-medium">{format(new Date(selectedSlot), 'h:mm a')}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Duration:</dt>
                <dd className="font-medium">60 minutes</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Fee:</dt>
                <dd className="font-medium">
                  ₹{nutritionists?.find((n: any) => n.id === selectedNutritionist)?.consultationFee}
                </dd>
              </div>
            </dl>

            <div className="mt-6 flex gap-4">
              <Button
                variant="outline"
                onClick={() => router.push('/dashboard/consultations')}
                className="flex-1"
              >
                Cancel
              </Button>
              <Button
                onClick={handleBooking}
                disabled={bookConsultation.isPending}
                className="flex-1"
              >
                {bookConsultation.isPending && (
                  <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                )}
                Confirm Booking
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
```

## Week 11: Admin Dashboard & Analytics

### Day 1-3: Admin Dashboard Setup

#### 1. Admin Layout
```typescript
// apps/web/app/admin/layout.tsx
import { redirect } from 'next/navigation';
import { getServerSession } from 'next-auth';
import { AdminNav } from '@/components/admin/nav';
import { AdminHeader } from '@/components/admin/header';
import { authOptions } from '@/lib/auth';

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession(authOptions);

  if (!session || session.user.role !== 'ADMIN') {
    redirect('/');
  }

  return (
    <div className="flex min-h-screen flex-col">
      <AdminHeader user={session.user} />
      <div className="flex-1 items-start md:grid md:grid-cols-[220px_minmax(0,1fr)] md:gap-6 lg:grid-cols-[240px_minmax(0,1fr)] lg:gap-10">
        <aside className="fixed top-14 z-30 hidden h-[calc(100vh-3.5rem)] w-full shrink-0 overflow-y-auto border-r md:sticky md:block">
          <AdminNav />
        </aside>
        <main className="flex w-full flex-col overflow-hidden p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
```

#### 2. Admin Dashboard Overview
```typescript
// apps/web/app/admin/page.tsx
'use client';

import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Icons } from '@/components/icons';
import { RevenueChart } from '@/components/admin/revenue-chart';
import { UserGrowthChart } from '@/components/admin/user-growth-chart';
import { ProgramPerformance } from '@/components/admin/program-performance';
import { RecentUsers } from '@/components/admin/recent-users';
import { TopNutritionists } from '@/components/admin/top-nutritionists';
import { api } from '@/lib/api';

export default function AdminDashboard() {
  const { data: stats } = useQuery({
    queryKey: ['admin-stats'],
    queryFn: async () => {
      const response = await api.get('/admin/stats');
      return response.data;
    },
  });

  const { data: revenue } = useQuery({
    queryKey: ['admin-revenue'],
    queryFn: async () => {
      const response = await api.get('/admin/revenue');
      return response.data;
    },
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Admin Dashboard</h1>
        <p className="text-muted-foreground">
          Monitor platform performance and manage operations
        </p>
      </div>

      {/* Key Metrics */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Revenue</CardTitle>
            <Icons.dollarSign className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              ₹{stats?.totalRevenue?.toLocaleString() || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              +{stats?.revenueGrowth || 0}% from last month
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Users</CardTitle>
            <Icons.users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.activeUsers || 0}</div>
            <p className="text-xs text-muted-foreground">
              +{stats?.userGrowth || 0}% from last month
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Consultations</CardTitle>
            <Icons.calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.totalConsultations || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.upcomingConsultations || 0} scheduled this week
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            <Icons.trendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.successRate || 0}%</div>
            <p className="text-xs text-muted-foreground">
              Program completion rate
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Analytics Tabs */}
      <Tabs defaultValue="revenue" className="space-y-4">
        <TabsList>
          <TabsTrigger value="revenue">Revenue</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="programs">Programs</TabsTrigger>
          <TabsTrigger value="nutritionists">Nutritionists</TabsTrigger>
        </TabsList>

        <TabsContent value="revenue" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
            <Card className="col-span-4">
              <CardHeader>
                <CardTitle>Revenue Overview</CardTitle>
                <CardDescription>
                  Monthly revenue trends and projections
                </CardDescription>
              </CardHeader>
              <CardContent>
                <RevenueChart data={revenue} />
              </CardContent>
            </Card>

            <Card className="col-span-3">
              <CardHeader>
                <CardTitle>Revenue Breakdown</CardTitle>
                <CardDescription>Revenue by source</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Programs</span>
                      <span className="text-sm font-bold">
                        ₹{stats?.revenueBySource?.programs?.toLocaleString() || 0}
                      </span>
                    </div>
                    <Progress
                      value={stats?.revenueBySource?.programsPercentage || 0}
                      className="h-2"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Consultations</span>
                      <span className="text-sm font-bold">
                        ₹{stats?.revenueBySource?.consultations?.toLocaleString() || 0}
                      </span>
                    </div>
                    <Progress
                      value={stats?.revenueBySource?.consultationsPercentage || 0}
                      className="h-2"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Resources</span>
                      <span className="text-sm font-bold">
                        ₹{stats?.revenueBySource?.resources?.toLocaleString() || 0}
                      </span>
                    </div>
                    <Progress
                      value={stats?.revenueBySource?.resourcesPercentage || 0}
                      className="h-2"
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="users">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>User Growth</CardTitle>
                <CardDescription>New user registrations over time</CardDescription>
              </CardHeader>
              <CardContent>
                <UserGrowthChart />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Recent Users</CardTitle>
                <CardDescription>Latest user registrations</CardDescription>
              </CardHeader>
              <CardContent>
                <RecentUsers />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="programs">
          <ProgramPerformance />
        </TabsContent>

        <TabsContent value="nutritionists">
          <TopNutritionists />
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

### Day 4-5: User Management

#### 1. User Management Page
```typescript
// apps/web/app/admin/users/page.tsx
'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ColumnDef } from '@tanstack/react-table';
import { DataTable } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Icons } from '@/components/icons';
import { UserDetailsDialog } from '@/components/admin/user-details-dialog';
import { api } from '@/lib/api';
import { format } from 'date-fns';

interface User {
  id: string;
  email: string;
  profile: {
    firstName: string;
    lastName: string;
    avatar?: string;
  };
  role: string;
  emailVerified: boolean;
  createdAt: string;
  lastLoginAt?: string;
  _count: {
    consultations: number;
    journeys: number;
  };
}

export default function UsersPage() {
  const [search, setSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['admin-users', search, page],
    queryFn: async () => {
      const response = await api.get('/admin/users', {
        params: { search, page, limit: 20 },
      });
      return response.data;
    },
  });

  const columns: ColumnDef<User>[] = [
    {
      accessorKey: 'profile',
      header: 'User',
      cell: ({ row }) => {
        const user = row.original;
        return (
          <div className="flex items-center gap-3">
            <Avatar className="h-8 w-8">
              <AvatarImage src={user.profile.avatar} />
              <AvatarFallback>
                {user.profile.firstName?.[0]}
                {user.profile.lastName?.[0]}
              </AvatarFallback>
            </Avatar>
            <div>
              <p className="font-medium">
                {user.profile.firstName} {user.profile.lastName}
              </p>
              <p className="text-sm text-muted-foreground">{user.email}</p>
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: 'role',
      header: 'Role',
      cell: ({ row }) => {
        const role = row.getValue('role') as string;
        return (
          <Badge variant={role === 'ADMIN' ? 'destructive' : 'default'}>
            {role}
          </Badge>
        );
      },
    },
    {
      accessorKey: 'emailVerified',
      header: 'Status',
      cell: ({ row }) => {
        const verified = row.getValue('emailVerified') as boolean;
        return (
          <Badge variant={verified ? 'success' : 'secondary'}>
            {verified ? 'Verified' : 'Unverified'}
          </Badge>
        );
      },
    },
    {
      accessorKey: '_count.consultations',
      header: 'Consultations',
    },
    {
      accessorKey: '_count.journeys',
      header: 'Programs',
    },
    {
      accessorKey: 'createdAt',
      header: 'Joined',
      cell: ({ row }) => {
        return format(new Date(row.getValue('createdAt')), 'MMM d, yyyy');
      },
    },
    {
      accessorKey: 'lastLoginAt',
      header: 'Last Active',
      cell: ({ row }) => {
        const date = row.getValue('lastLoginAt') as string | null;
        return date ? format(new Date(date), 'MMM d, yyyy') : 'Never';
      },
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const user = row.original;
        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="h-8 w-8 p-0">
                <span className="sr-only">Open menu</span>
                <Icons.moreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Actions</DropdownMenuLabel>
              <DropdownMenuItem onClick={() => setSelectedUser(user)}>
                <Icons.eye className="mr-2 h-4 w-4" />
                View details
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Icons.mail className="mr-2 h-4 w-4" />
                Send email
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <Icons.userCheck className="mr-2 h-4 w-4" />
                Change role
              </DropdownMenuItem>
              <DropdownMenuItem className="text-red-600">
                <Icons.userX className="mr-2 h-4 w-4" />
                Suspend user
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Users</h1>
        <p className="text-muted-foreground">
          Manage user accounts and permissions
        </p>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Icons.search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search users..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Button>
          <Icons.download className="mr-2 h-4 w-4" />
          Export
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={data?.users || []}
        loading={isLoading}
        pagination={{
          page,
          pageSize: 20,
          total: data?.total || 0,
          onPageChange: setPage,
        }}
      />

      <UserDetailsDialog
        user={selectedUser}
        open={!!selectedUser}
        onOpenChange={(open) => !open && setSelectedUser(null)}
      />
    </div>
  );
}
```

### Day 6-7: Analytics Dashboard

#### 1. Analytics Service
```typescript
// apps/web/lib/analytics.ts
import { useEffect } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';

declare global {
  interface Window {
    gtag: (
      type: string,
      action: string,
      options?: {
        page_path?: string;
        event_category?: string;
        event_label?: string;
        value?: number;
        [key: string]: any;
      }
    ) => void;
  }
}

export const GA_TRACKING_ID = process.env.NEXT_PUBLIC_GA_ID;

// Track page views
export const pageview = (url: string) => {
  if (typeof window !== 'undefined' && window.gtag) {
    window.gtag('config', GA_TRACKING_ID!, {
      page_path: url,
    });
  }
};

// Track events
export const event = ({
  action,
  category,
  label,
  value,
  ...otherParams
}: {
  action: string;
  category: string;
  label?: string;
  value?: number;
  [key: string]: any;
}) => {
  if (typeof window !== 'undefined' && window.gtag) {
    window.gtag('event', action, {
      event_category: category,
      event_label: label,
      value: value,
      ...otherParams,
    });
  }
};

// Analytics hook
export function useAnalytics() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    const url = pathname + searchParams.toString();
    pageview(url);
  }, [pathname, searchParams]);

  return {
    trackEvent: event,
    trackPageView: pageview,
  };
}

// Pre-defined events
export const trackEvents = {
  // Authentication
  signUp: (method: string) =>
    event({
      action: 'sign_up',
      category: 'authentication',
      label: method,
    }),

  login: (method: string) =>
    event({
      action: 'login',
      category: 'authentication',
      label: method,
    }),

  // Consultation
  bookConsultation: (nutritionistId: string, price: number) =>
    event({
      action: 'book_consultation',
      category: 'consultation',
      label: nutritionistId,
      value: price,
    }),

  cancelConsultation: (consultationId: string) =>
    event({
      action: 'cancel_consultation',
      category: 'consultation',
      label: consultationId,
    }),

  // Program
  enrollProgram: (programId: string, programName: string, price: number) =>
    event({
      action: 'enroll_program',
      category: 'program',
      label: programName,
      value: price,
      program_id: programId,
    }),

  completeProgram: (programId: string, programName: string) =>
    event({
      action: 'complete_program',
      category: 'program',
      label: programName,
      program_id: programId,
    }),

  // Quiz
  startQuiz: (quizType: string) =>
    event({
      action: 'start_quiz',
      category: 'quiz',
      label: quizType,
    }),

  completeQuiz: (quizType: string, score: number) =>
    event({
      action: 'complete_quiz',
      category: 'quiz',
      label: quizType,
      value: score,
    }),

  // Content
  viewContent: (contentType: string, contentId: string, contentTitle: string) =>
    event({
      action: 'view_content',
      category: 'content',
      label: contentTitle,
      content_type: contentType,
      content_id: contentId,
    }),

  downloadResource: (resourceId: string, resourceTitle: string) =>
    event({
      action: 'download_resource',
      category: 'content',
      label: resourceTitle,
      resource_id: resourceId,
    }),

  // Payment
  initiatePayment: (amount: number, item: string) =>
    event({
      action: 'begin_checkout',
      category: 'ecommerce',
      value: amount,
      currency: 'INR',
      items: [{ item_name: item }],
    }),

  completePayment: (amount: number, item: string, paymentMethod: string) =>
    event({
      action: 'purchase',
      category: 'ecommerce',
      value: amount,
      currency: 'INR',
      payment_method: paymentMethod,
      items: [{ item_name: item }],
    }),

  // User Engagement
  shareContent: (contentType: string, method: string) =>
    event({
      action: 'share',
      category: 'engagement',
      label: `${contentType}_${method}`,
    }),

  contactSupport: (method: string) =>
    event({
      action: 'contact_support',
      category: 'engagement',
      label: method,
    }),
};
```

#### 2. Analytics Dashboard Component
```typescript
// apps/web/app/admin/analytics/page.tsx
'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { DatePickerWithRange } from '@/components/ui/date-range-picker';
import { Icons } from '@/components/icons';
import { UserBehaviorFlow } from '@/components/analytics/user-behavior-flow';
import { ConversionFunnel } from '@/components/analytics/conversion-funnel';
import { ContentPerformance } from '@/components/analytics/content-performance';
import { RevenueAnalytics } from '@/components/analytics/revenue-analytics';
import { HealthOutcomes } from '@/components/analytics/health-outcomes';
import { api } from '@/lib/api';
import { DateRange } from 'react-day-picker';
import { subDays } from 'date-fns';

export default function AnalyticsPage() {
  const [dateRange, setDateRange] = useState<DateRange>({
    from: subDays(new Date(), 30),
    to: new Date(),
  });

  const [segment, setSegment] = useState<string>('all');

  const { data: overview } = useQuery({
    queryKey: ['analytics-overview', dateRange, segment],
    queryFn: async () => {
      const response = await api.get('/admin/analytics/overview', {
        params: {
          startDate: dateRange.from?.toISOString(),
          endDate: dateRange.to?.toISOString(),
          segment,
        },
      });
      return response.data;
    },
  });

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Analytics</h1>
          <p className="text-muted-foreground">
            Comprehensive insights into platform performance
          </p>
        </div>

        <div className="flex items-center gap-4">
          <Select value={segment} onValueChange={setSegment}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Select segment" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Users</SelectItem>
              <SelectItem value="new">New Users</SelectItem>
              <SelectItem value="active">Active Users</SelectItem>
              <SelectItem value="premium">Premium Users</SelectItem>
            </SelectContent>
          </Select>

          <DatePickerWithRange
            date={dateRange}
            onDateChange={setDateRange}
          />
        </div>
      </div>

      {/* Key Metrics Overview */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Icons.users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.totalUsers || 0}</div>
            <p className="text-xs text-muted-foreground">
              {overview?.userGrowth > 0 ? '+' : ''}{overview?.userGrowth || 0}% vs previous
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Conversion Rate</CardTitle>
            <Icons.trendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.conversionRate || 0}%</div>
            <p className="text-xs text-muted-foreground">
              Visitor to customer
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Session</CardTitle>
            <Icons.clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.avgSessionDuration || '0m'}</div>
            <p className="text-xs text-muted-foreground">
              Per user session
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Retention</CardTitle>
            <Icons.userCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.retentionRate || 0}%</div>
            <p className="text-xs text-muted-foreground">
              30-day retention
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">LTV</CardTitle>
            <Icons.dollarSign className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">₹{overview?.avgLTV || 0}</div>
            <p className="text-xs text-muted-foreground">
              Lifetime value
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Detailed Analytics */}
      <Tabs defaultValue="behavior" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="behavior">User Behavior</TabsTrigger>
          <TabsTrigger value="conversion">Conversion</TabsTrigger>
          <TabsTrigger value="content">Content</TabsTrigger>
          <TabsTrigger value="revenue">Revenue</TabsTrigger>
          <TabsTrigger value="outcomes">Health Outcomes</TabsTrigger>
        </TabsList>

        <TabsContent value="behavior">
          <UserBehaviorFlow dateRange={dateRange} segment={segment} />
        </TabsContent>

        <TabsContent value="conversion">
          <ConversionFunnel dateRange={dateRange} segment={segment} />
        </TabsContent>

        <TabsContent value="content">
          <ContentPerformance dateRange={dateRange} />
        </TabsContent>

        <TabsContent value="revenue">
          <RevenueAnalytics dateRange={dateRange} segment={segment} />
        </TabsContent>

        <TabsContent value="outcomes">
          <HealthOutcomes dateRange={dateRange} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

## Week 12: Testing, Optimization & Deployment

### Day 1-2: Testing Setup

#### 1. Unit Testing Configuration
```typescript
// jest.config.js
const nextJest = require('next/jest');

const createJestConfig = nextJest({
  dir: './',
});

const customJestConfig = {
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  moduleNameMapper: {
    '^@/(.*)# Comprehensive Weekly Implementation Guide - Functional Nutrition Platform

## Week 1: Project Foundation & Infrastructure Setup

### Day 1-2: Repository and Monorepo Setup

#### 1. Initialize Monorepo Structure
```bash
# Create project directory
mkdir nutrition-platform && cd nutrition-platform

# Initialize git repository
git init

# Create monorepo structure
mkdir -p apps/{web,api,admin,mobile-pwa}
mkdir -p packages/{ui,utils,types,config,database}
mkdir -p services/{auth,user,consultation,payment,content,quiz,notification,analytics}
mkdir -p infrastructure/{docker,kubernetes,terraform,scripts}
mkdir -p docs/{api,architecture,deployment}

# Initialize npm workspaces
npm init -y
```

#### 2. Setup package.json for Workspaces
```json
{
  "name": "nutrition-platform",
  "private": true,
  "workspaces": [
    "apps/*",
    "packages/*",
    "services/*"
  ],
  "scripts": {
    "dev": "turbo run dev",
    "build": "turbo run build",
    "test": "turbo run test",
    "lint": "turbo run lint",
    "format": "prettier --write \"**/*.{ts,tsx,js,jsx,json,md}\"",
    "prepare": "husky install"
  },
  "devDependencies": {
    "turbo": "^1.11.0",
    "@types/node": "^20.10.0",
    "typescript": "^5.3.0",
    "prettier": "^3.1.0",
    "eslint": "^8.55.0",
    "husky": "^8.0.3",
    "lint-staged": "^15.2.0"
  }
}
```

#### 3. Setup Turborepo Configuration
```json
// turbo.json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": [".next/**", "dist/**"]
    },
    "dev": {
      "cache": false,
      "persistent": true
    },
    "test": {
      "dependsOn": ["build"],
      "inputs": ["src/**", "tests/**"]
    },
    "lint": {},
    "type-check": {}
  }
}
```

#### 4. Setup TypeScript Configuration
```json
// tsconfig.base.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "jsx": "preserve",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "moduleResolution": "node",
    "baseUrl": ".",
    "paths": {
      "@nutrition/*": ["packages/*/src"]
    }
  },
  "exclude": ["node_modules", "dist", ".next", "coverage"]
}
```

### Day 3-4: Docker Environment Setup

#### 1. Create Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: nutrition_postgres
    environment:
      POSTGRES_USER: nutrition_user
      POSTGRES_PASSWORD: nutrition_password
      POSTGRES_DB: nutrition_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./infrastructure/docker/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nutrition_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: nutrition_redis
    command: redis-server --requirepass nutrition_redis_password
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    container_name: nutrition_minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: nutrition_minio_user
      MINIO_ROOT_PASSWORD: nutrition_minio_password
    volumes:
      - minio_data:/data
    ports:
      - "9000:9000"
      - "9001:9001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 20s
      retries: 3

  meilisearch:
    image: getmeili/meilisearch:latest
    container_name: nutrition_meilisearch
    environment:
      MEILI_MASTER_KEY: nutrition_meilisearch_key
      MEILI_ENV: development
    volumes:
      - meilisearch_data:/meili_data
    ports:
      - "7700:7700"

  mailhog:
    image: mailhog/mailhog:latest
    container_name: nutrition_mailhog
    ports:
      - "1025:1025"
      - "8025:8025"

volumes:
  postgres_data:
  redis_data:
  minio_data:
  meilisearch_data:
```

#### 2. Create Development Dockerfile
```dockerfile
# Dockerfile.dev
FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat
RUN apk update
WORKDIR /app

# Install dependencies
FROM base AS deps
COPY package.json package-lock.json ./
COPY apps/*/package.json apps/*/
COPY packages/*/package.json packages/*/
COPY services/*/package.json services/*/
RUN npm ci

# Development
FROM base AS dev
COPY --from=deps /app/node_modules ./node_modules
COPY . .
EXPOSE 3000 4000
CMD ["npm", "run", "dev"]
```

### Day 5: CI/CD Pipeline Setup

#### 1. GitHub Actions Configuration
```yaml
# .github/workflows/main.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  NODE_VERSION: '20'
  PNPM_VERSION: '8'

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Run ESLint
        run: npm run lint
      - name: Run Type Check
        run: npm run type-check

  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test_password
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Run unit tests
        run: npm run test:unit
      - name: Run integration tests
        run: npm run test:integration
        env:
          DATABASE_URL: postgresql://postgres:test_password@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379

  build:
    needs: [lint, test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Build applications
        run: npm run build
      - name: Build Docker images
        run: |
          docker build -f Dockerfile.api -t nutrition-api:${{ github.sha }} .
          docker build -f Dockerfile.web -t nutrition-web:${{ github.sha }} .
      - name: Push to registry
        if: github.ref == 'refs/heads/main'
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push nutrition-api:${{ github.sha }}
          docker push nutrition-web:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Deploy to staging
        run: |
          # Deploy to Kubernetes or other platform
          echo "Deploying to staging..."
```

#### 2. Environment Configuration
```bash
# .env.example
# Application
NODE_ENV=development
PORT=4000
CLIENT_URL=http://localhost:3000
API_URL=http://localhost:4000

# Database
DATABASE_URL=postgresql://nutrition_user:nutrition_password@localhost:5432/nutrition_db
REDIS_URL=redis://:nutrition_redis_password@localhost:6379

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# 2FA
TWO_FA_APP_NAME=NutritionPlatform

# File Storage
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_ACCESS_KEY=nutrition_minio_user
MINIO_SECRET_KEY=nutrition_minio_password
MINIO_BUCKET=nutrition-uploads

# Search
MEILISEARCH_HOST=http://localhost:7700
MEILISEARCH_KEY=nutrition_meilisearch_key

# Email (Development)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=
SMTP_PASS=
EMAIL_FROM=noreply@nutritionplatform.com

# Payment Gateway
RAZORPAY_KEY_ID=your_razorpay_key
RAZORPAY_KEY_SECRET=your_razorpay_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# WhatsApp
WHATSAPP_API_URL=https://api.whatsapp.com/v1
WHATSAPP_TOKEN=your_whatsapp_token
WHATSAPP_PHONE_ID=your_phone_id

# SMS
SMS_PROVIDER=msg91
MSG91_AUTH_KEY=your_msg91_key
MSG91_SENDER_ID=NUTRIT

# Analytics
GA_TRACKING_ID=G-XXXXXXXXXX
HOTJAR_SITE_ID=1234567

# PayloadCMS
PAYLOAD_SECRET=your-payload-secret
PAYLOAD_CONFIG_PATH=src/payload.config.ts
```

### Day 6-7: Database Schema Implementation

#### 1. Prisma Setup and Schema
```bash
# Install Prisma
cd packages/database
npm init -y
npm install prisma @prisma/client
npm install -D @types/node typescript

# Initialize Prisma
npx prisma init
```

```prisma
// packages/database/prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// Enums
enum UserRole {
  USER
  NUTRITIONIST
  ADMIN
}

enum Gender {
  MALE
  FEMALE
  OTHER
  PREFER_NOT_TO_SAY
}

enum ConsultationStatus {
  SCHEDULED
  IN_PROGRESS
  COMPLETED
  CANCELLED
  NO_SHOW
}

enum PaymentStatus {
  PENDING
  PROCESSING
  SUCCESS
  FAILED
  REFUNDED
}

enum ProgramType {
  GUT_HEALTH
  METABOLIC_RESET
  PCOS_RESTORE
  DIABETES_CARE
  DETOX_HORMONE
  CUSTOM
}

enum QuizType {
  SYMPTOM
  GUT_HEALTH
  STRESS
  NUTRITION
  LIFESTYLE
}

// Models
model User {
  id              String    @id @default(uuid())
  email           String    @unique
  phone           String?   @unique
  passwordHash    String    @map("password_hash")
  role            UserRole  @default(USER)
  emailVerified   Boolean   @default(false) @map("email_verified")
  phoneVerified   Boolean   @default(false) @map("phone_verified")
  twoFASecret     String?   @map("two_fa_secret")
  twoFAEnabled    Boolean   @default(false) @map("two_fa_enabled")
  lastLoginAt     DateTime? @map("last_login_at")
  createdAt       DateTime  @default(now()) @map("created_at")
  updatedAt       DateTime  @updatedAt @map("updated_at")

  // Relations
  profile              UserProfile?
  consultations        Consultation[]
  payments            Payment[]
  quizResults         QuizResult[]
  journeys            UserJourney[]
  documents           Document[]
  notifications       Notification[]
  refreshTokens       RefreshToken[]
  nutritionistProfile NutritionistProfile?
  consultationsAsNutritionist Consultation[] @relation("NutritionistConsultations")

  @@map("users")
  @@index([email])
  @@index([phone])
}

model UserProfile {
  id            String    @id @default(uuid())
  userId        String    @unique @map("user_id")
  firstName     String    @map("first_name")
  lastName      String    @map("last_name")
  dateOfBirth   DateTime? @map("date_of_birth")
  gender        Gender?
  avatar        String?
  bio           String?
  height        Float?    // in cm
  weight        Float?    // in kg
  bloodGroup    String?   @map("blood_group")
  allergies     String[]
  medications   String[]
  medicalHistory Json?    @map("medical_history")
  preferences   Json?
  timezone      String    @default("Asia/Kolkata")
  language      String    @default("en")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("user_profiles")
}

model NutritionistProfile {
  id                String   @id @default(uuid())
  userId            String   @unique @map("user_id")
  registrationNumber String?  @map("registration_number")
  qualifications    String[]
  specializations   String[]
  experience        Int      // in years
  aboutMe           String?  @map("about_me")
  consultationFee   Float    @map("consultation_fee")
  languages         String[]
  availability      Json?    // Weekly availability schedule
  rating            Float    @default(0)
  totalReviews      Int      @default(0) @map("total_reviews")
  isActive          Boolean  @default(true) @map("is_active")
  createdAt         DateTime @default(now()) @map("created_at")
  updatedAt         DateTime @updatedAt @map("updated_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("nutritionist_profiles")
}

model Program {
  id              String      @id @default(uuid())
  name            String
  slug            String      @unique
  type            ProgramType
  description     String
  shortDescription String?    @map("short_description")
  duration        Int         // in days
  price           Float
  discountedPrice Float?      @map("discounted_price")
  currency        String      @default("INR")
  features        String[]
  includes        Json?       // Detailed list of what's included
  outcomes        String[]    // Expected outcomes
  whoIsItFor      String[]    @map("who_is_it_for")
  image           String?
  isActive        Boolean     @default(true) @map("is_active")
  isFeatured      Boolean     @default(false) @map("is_featured")
  order           Int         @default(0)
  metadata        Json?
  createdAt       DateTime    @default(now()) @map("created_at")
  updatedAt       DateTime    @updatedAt @map("updated_at")

  // Relations
  consultations Consultation[]
  journeys      UserJourney[]
  reviews       ProgramReview[]

  @@map("programs")
  @@index([slug])
  @@index([type])
}

model Consultation {
  id               String             @id @default(uuid())
  userId           String             @map("user_id")
  nutritionistId   String             @map("nutritionist_id")
  programId        String?            @map("program_id")
  scheduledAt      DateTime           @map("scheduled_at")
  duration         Int                // in minutes
  status           ConsultationStatus @default(SCHEDULED)
  meetingLink      String?            @map("meeting_link")
  meetingId        String?            @map("meeting_id")
  notes            String?
  internalNotes    String?            @map("internal_notes")
  recordingUrl     String?            @map("recording_url")
  prescription     Json?              // Structured prescription data
  followUpDate     DateTime?          @map("follow_up_date")
  completedAt      DateTime?          @map("completed_at")
  cancelledAt      DateTime?          @map("cancelled_at")
  cancellationReason String?          @map("cancellation_reason")
  createdAt        DateTime           @default(now()) @map("created_at")
  updatedAt        DateTime           @updatedAt @map("updated_at")

  // Relations
  user         User     @relation(fields: [userId], references: [id])
  nutritionist User     @relation("NutritionistConsultations", fields: [nutritionistId], references: [id])
  program      Program? @relation(fields: [programId], references: [id])
  payment      Payment?
  reminders    ConsultationReminder[]

  @@map("consultations")
  @@index([userId])
  @@index([nutritionistId])
  @@index([scheduledAt])
  @@index([status])
}

model ConsultationReminder {
  id              String       @id @default(uuid())
  consultationId  String       @map("consultation_id")
  type            String       // email, sms, whatsapp
  scheduledAt     DateTime     @map("scheduled_at")
  sentAt          DateTime?    @map("sent_at")
  status          String       // pending, sent, failed
  createdAt       DateTime     @default(now()) @map("created_at")

  // Relations
  consultation Consultation @relation(fields: [consultationId], references: [id], onDelete: Cascade)

  @@map("consultation_reminders")
  @@index([consultationId])
  @@index([scheduledAt])
}

model Payment {
  id                  String        @id @default(uuid())
  userId              String        @map("user_id")
  consultationId      String?       @unique @map("consultation_id")
  journeyId           String?       @map("journey_id")
  amount              Float
  currency            String        @default("INR")
  status              PaymentStatus @default(PENDING)
  gateway             String        // razorpay, cashfree
  gatewayOrderId      String?       @map("gateway_order_id")
  gatewayPaymentId    String?       @map("gateway_payment_id")
  gatewaySignature    String?       @map("gateway_signature")
  paymentMethod       String?       @map("payment_method")
  refundId            String?       @map("refund_id")
  refundAmount        Float?        @map("refund_amount")
  refundedAt          DateTime?     @map("refunded_at")
  metadata            Json?
  invoiceNumber       String?       @unique @map("invoice_number")
  invoiceUrl          String?       @map("invoice_url")
  receiptUrl          String?       @map("receipt_url")
  failureReason       String?       @map("failure_reason")
  createdAt           DateTime      @default(now()) @map("created_at")
  updatedAt           DateTime      @updatedAt @map("updated_at")

  // Relations
  user         User          @relation(fields: [userId], references: [id])
  consultation Consultation? @relation(fields: [consultationId], references: [id])
  journey      UserJourney?  @relation(fields: [journeyId], references: [id])

  @@map("payments")
  @@index([userId])
  @@index([status])
  @@index([gatewayOrderId])
  @@index([invoiceNumber])
}

model UserJourney {
  id            String    @id @default(uuid())
  userId        String    @map("user_id")
  programId     String    @map("program_id")
  startDate     DateTime  @map("start_date")
  endDate       DateTime? @map("end_date")
  status        String    @default("ACTIVE") // ACTIVE, PAUSED, COMPLETED, CANCELLED
  progress      Json?     // Milestone tracking
  measurements  Json?     // Weight, BMI, other health metrics over time
  mealPlans     Json?     @map("meal_plans")
  supplements   Json?
  notes         String?
  completedAt   DateTime? @map("completed_at")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  // Relations
  user         User          @relation(fields: [userId], references: [id])
  program      Program       @relation(fields: [programId], references: [id])
  payments     Payment[]
  checkIns     JourneyCheckIn[]
  mealEntries  MealEntry[]

  @@map("user_journeys")
  @@index([userId])
  @@index([programId])
  @@index([status])
}

model JourneyCheckIn {
  id          String      @id @default(uuid())
  journeyId   String      @map("journey_id")
  date        DateTime
  weight      Float?
  energy      Int?        // 1-10 scale
  mood        Int?        // 1-10 scale
  sleep       Float?      // hours
  exercise    Int?        // minutes
  water       Float?      // liters
  symptoms    String[]
  notes       String?
  photos      String[]    // URLs
  createdAt   DateTime    @default(now()) @map("created_at")

  // Relations
  journey UserJourney @relation(fields: [journeyId], references: [id], onDelete: Cascade)

  @@map("journey_check_ins")
  @@index([journeyId])
  @@index([date])
}

model MealEntry {
  id          String      @id @default(uuid())
  journeyId   String      @map("journey_id")
  date        DateTime
  mealType    String      @map("meal_type") // breakfast, lunch, dinner, snack
  foods       Json        // Array of food items with quantities
  calories    Float?
  protein     Float?      // in grams
  carbs       Float?      // in grams
  fat         Float?      // in grams
  fiber       Float?      // in grams
  notes       String?
  photo       String?
  createdAt   DateTime    @default(now()) @map("created_at")

  // Relations
  journey UserJourney @relation(fields: [journeyId], references: [id], onDelete: Cascade)

  @@map("meal_entries")
  @@index([journeyId])
  @@index([date])
}

model Quiz {
  id          String      @id @default(uuid())
  type        QuizType
  title       String
  description String?
  questions   Json        // Array of questions with options
  scoring     Json        // Scoring logic
  isActive    Boolean     @default(true) @map("is_active")
  createdAt   DateTime    @default(now()) @map("created_at")
  updatedAt   DateTime    @updatedAt @map("updated_at")

  // Relations
  results QuizResult[]

  @@map("quizzes")
  @@index([type])
}

model QuizResult {
  id              String   @id @default(uuid())
  userId          String?  @map("user_id")
  quizId          String   @map("quiz_id")
  quizType        QuizType @map("quiz_type")
  responses       Json     // User's answers
  score           Int?
  analysis        Json?    // Detailed analysis
  recommendations Json?    // Program/action recommendations
  ipAddress       String?  @map("ip_address")
  userAgent       String?  @map("user_agent")
  completedAt     DateTime @default(now()) @map("completed_at")

  // Relations
  user User? @relation(fields: [userId], references: [id])
  quiz Quiz  @relation(fields: [quizId], references: [id])

  @@map("quiz_results")
  @@index([userId])
  @@index([quizId])
  @@index([quizType])
}

model BlogPost {
  id            String    @id @default(uuid())
  title         String
  slug          String    @unique
  excerpt       String?
  content       String    @db.Text
  featuredImage String?   @map("featured_image")
  author        String
  category      String
  tags          String[]
  readTime      Int?      @map("read_time") // in minutes
  isPublished   Boolean   @default(false) @map("is_published")
  publishedAt   DateTime? @map("published_at")
  seoTitle      String?   @map("seo_title")
  seoDescription String?  @map("seo_description")
  seoKeywords   String[]  @map("seo_keywords")
  viewCount     Int       @default(0) @map("view_count")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  @@map("blog_posts")
  @@index([slug])
  @@index([category])
  @@index([isPublished])
}

model Resource {
  id            String   @id @default(uuid())
  title         String
  description   String?
  type          String   // pdf, video, calculator, tracker
  category      String
  fileUrl       String?  @map("file_url")
  thumbnailUrl  String?  @map("thumbnail_url")
  isPublic      Boolean  @default(true) @map("is_public")
  requiresAuth  Boolean  @default(false) @map("requires_auth")
  downloadCount Int      @default(0) @map("download_count")
  tags          String[]
  metadata      Json?
  createdAt     DateTime @default(now()) @map("created_at")
  updatedAt     DateTime @updatedAt @map("updated_at")

  @@map("resources")
  @@index([type])
  @@index([category])
}

model Document {
  id           String   @id @default(uuid())
  userId       String   @map("user_id")
  type         String   // medical_report, prescription, meal_plan, etc
  title        String
  description  String?
  fileUrl      String   @map("file_url")
  fileSize     Int      @map("file_size") // in bytes
  mimeType     String   @map("mime_type")
  isArchived   Boolean  @default(false) @map("is_archived")
  metadata     Json?
  uploadedAt   DateTime @default(now()) @map("uploaded_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("documents")
  @@index([userId])
  @@index([type])
}

model Notification {
  id         String    @id @default(uuid())
  userId     String    @map("user_id")
  type       String    // email, sms, whatsapp, in-app
  category   String    // consultation, payment, journey, system
  title      String
  content    String
  data       Json?     // Additional data for the notification
  status     String    @default("PENDING") // PENDING, SENT, FAILED
  readAt     DateTime? @map("read_at")
  sentAt     DateTime? @map("sent_at")
  error      String?
  createdAt  DateTime  @default(now()) @map("created_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("notifications")
  @@index([userId])
  @@index([status])
  @@index([type])
}

model RefreshToken {
  id          String   @id @default(uuid())
  userId      String   @map("user_id")
  token       String   @unique
  expiresAt   DateTime @map("expires_at")
  createdAt   DateTime @default(now()) @map("created_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("refresh_tokens")
  @@index([token])
  @@index([userId])
}

model ProgramReview {
  id         String   @id @default(uuid())
  programId  String   @map("program_id")
  userId     String   @map("user_id")
  rating     Int      // 1-5
  title      String?
  comment    String?
  isVerified Boolean  @default(false) @map("is_verified")
  createdAt  DateTime @default(now()) @map("created_at")
  updatedAt  DateTime @updatedAt @map("updated_at")

  // Relations
  program Program @relation(fields: [programId], references: [id])

  @@map("program_reviews")
  @@unique([programId, userId])
  @@index([programId])
}

model AuditLog {
  id         String   @id @default(uuid())
  userId     String?  @map("user_id")
  action     String   // CREATE, UPDATE, DELETE, LOGIN, etc
  entity     String   // user, consultation, payment, etc
  entityId   String?  @map("entity_id")
  changes    Json?    // Before and after values
  ipAddress  String?  @map("ip_address")
  userAgent  String?  @map("user_agent")
  createdAt  DateTime @default(now()) @map("created_at")

  @@map("audit_logs")
  @@index([userId])
  @@index([entity])
  @@index([action])
  @@index([createdAt])
}
```

#### 2. Database Initialization Script
```sql
-- infrastructure/docker/postgres/init.sql
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create indexes for text search
CREATE INDEX idx_blog_posts_title_trgm ON blog_posts USING gin (title gin_trgm_ops);
CREATE INDEX idx_blog_posts_content_trgm ON blog_posts USING gin (content gin_trgm_ops);
CREATE INDEX idx_resources_title_trgm ON resources USING gin (title gin_trgm_ops);

-- Create functions for updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_profiles_updated_at BEFORE UPDATE ON user_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add more triggers for other tables...
```

## Week 2: Core Services & Authentication

### Day 1-2: Authentication Service Implementation

#### 1. Create Auth Service Structure
```bash
# Create auth service
cd services/auth
npm init -y
npm install express bcrypt jsonwebtoken speakeasy qrcode passport passport-jwt passport-local
npm install -D @types/express @types/bcrypt @types/jsonwebtoken @types/passport @types/passport-jwt @types/passport-local typescript nodemon

# Create folder structure
mkdir -p src/{controllers,services,middleware,routes,utils,validators,types}
touch src/index.ts
```

#### 2. Auth Service Configuration
```typescript
// services/auth/src/config/index.ts
import { config } from 'dotenv';
import path from 'path';

// Load environment variables
config({ path: path.join(__dirname, '../../../../.env') });

export const authConfig = {
  port: process.env.AUTH_SERVICE_PORT || 4001,
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    algorithm: 'HS256' as const,
  },
  bcrypt: {
    saltRounds: 12,
  },
  twoFA: {
    appName: process.env.TWO_FA_APP_NAME || 'NutritionPlatform',
    window: 1, // Allow 30 seconds time window
  },
  email: {
    verificationExpiry: 24 * 60 * 60 * 1000, // 24 hours
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5, // Limit each IP to 5 requests per windowMs
  },
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true,
  },
};
```

#### 3. Auth Types & Interfaces
```typescript
// services/auth/src/types/auth.types.ts
export interface JWTPayload {
  userId: string;
  email: string;
  role: UserRole;
  sessionId?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface RegisterDTO {
  email: string;
  password: string;
  phone?: string;
  firstName: string;
  lastName: string;
  acceptTerms: boolean;
}

export interface LoginDTO {
  email: string;
  password: string;
  twoFactorCode?: string;
}

export interface VerifyEmailDTO {
  token: string;
}

export interface Enable2FADTO {
  password: string;
}

export interface Verify2FADTO {
  token: string;
}

export enum UserRole {
  USER = 'USER',
  NUTRITIONIST = 'NUTRITIONIST',
  ADMIN = 'ADMIN',
}

export interface SessionData {
  userId: string;
  deviceInfo: {
    userAgent: string;
    ip: string;
    device?: string;
    browser?: string;
  };
  lastActivity: Date;
}
```

#### 4. JWT Service Implementation
```typescript
// services/auth/src/services/jwt.service.ts
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { authConfig } from '../config';
import { JWTPayload, AuthTokens } from '../types/auth.types';
import { redisClient } from '../utils/redis';
import { prisma } from '@nutrition/database';

export class JWTService {
  private static readonly ACCESS_TOKEN_PREFIX = 'access_token:';
  private static readonly REFRESH_TOKEN_PREFIX = 'refresh_token:';
  private static readonly BLACKLIST_PREFIX = 'blacklist:';

  static async generateTokens(payload: JWTPayload): Promise<AuthTokens> {
    const sessionId = uuidv4();
    const tokenPayload = { ...payload, sessionId };

    // Generate access token
    const accessToken = jwt.sign(
      tokenPayload,
      authConfig.jwt.secret,
      {
        expiresIn: authConfig.jwt.expiresIn,
        algorithm: authConfig.jwt.algorithm,
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { userId: payload.userId, sessionId },
      authConfig.jwt.refreshSecret,
      {
        expiresIn: authConfig.jwt.refreshExpiresIn,
        algorithm: authConfig.jwt.algorithm,
      }
    );

    // Store refresh token in database
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    await prisma.refreshToken.create({
      data: {
        userId: payload.userId,
        token: refreshToken,
        expiresAt,
      },
    });

    // Store session in Redis
    await redisClient.setex(
      `${this.ACCESS_TOKEN_PREFIX}${sessionId}`,
      15 * 60, // 15 minutes
      JSON.stringify(payload)
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: 15 * 60, // 15 minutes in seconds
    };
  }

  static async verifyAccessToken(token: string): Promise<JWTPayload> {
    try {
      // Check if token is blacklisted
      const isBlacklisted = await redisClient.get(`${this.BLACKLIST_PREFIX}${token}`);
      if (isBlacklisted) {
        throw new Error('Token is blacklisted');
      }

      const decoded = jwt.verify(token, authConfig.jwt.secret) as JWTPayload & { sessionId: string };
      
      // Verify session exists
      const session = await redisClient.get(`${this.ACCESS_TOKEN_PREFIX}${decoded.sessionId}`);
      if (!session) {
        throw new Error('Session not found');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  static async verifyRefreshToken(token: string): Promise<{ userId: string; sessionId: string }> {
    try {
      const decoded = jwt.verify(token, authConfig.jwt.refreshSecret) as { userId: string; sessionId: string };
      
      // Check if refresh token exists in database
      const refreshToken = await prisma.refreshToken.findUnique({
        where: { token },
      });

      if (!refreshToken || refreshToken.expiresAt < new Date()) {
        throw new Error('Invalid refresh token');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  static async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const { userId } = await this.verifyRefreshToken(refreshToken);

    // Get user details
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Delete old refresh token
    await prisma.refreshToken.delete({
      where: { token: refreshToken },
    });

    // Generate new tokens
    return this.generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role,
    });
  }

  static async revokeToken(token: string, sessionId?: string): Promise<void> {
    // Add token to blacklist
    const decoded = jwt.decode(token) as any;
    if (decoded && decoded.exp) {
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await redisClient.setex(`${this.BLACKLIST_PREFIX}${token}`, ttl, '1');
      }
    }

    // Remove session if provided
    if (sessionId) {
      await redisClient.del(`${this.ACCESS_TOKEN_PREFIX}${sessionId}`);
    }
  }

  static async revokeAllUserTokens(userId: string): Promise<void> {
    // Delete all refresh tokens
    await prisma.refreshToken.deleteMany({
      where: { userId },
    });

    // Note: Access tokens will expire naturally or need to track sessions differently
  }
}
```

#### 5. Password Service
```typescript
// services/auth/src/services/password.service.ts
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { authConfig } from '../config';
import { redisClient } from '../utils/redis';

export class PasswordService {
  private static readonly RESET_TOKEN_PREFIX = 'password_reset:';
  private static readonly RESET_TOKEN_EXPIRY = 3600; // 1 hour

  static async hash(password: string): Promise<string> {
    return bcrypt.hash(password, authConfig.bcrypt.saltRounds);
  }

  static async compare(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  static validateStrength(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async generateResetToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Store in Redis with expiry
    await redisClient.setex(
      `${this.RESET_TOKEN_PREFIX}${hashedToken}`,
      this.RESET_TOKEN_EXPIRY,
      userId
    );

    return token;
  }

  static async verifyResetToken(token: string): Promise<string | null> {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const userId = await redisClient.get(`${this.RESET_TOKEN_PREFIX}${hashedToken}`);

    if (!userId) {
      return null;
    }

    // Delete token after verification
    await redisClient.del(`${this.RESET_TOKEN_PREFIX}${hashedToken}`);
    return userId;
  }
}
```

#### 6. Two-Factor Authentication Service
```typescript
// services/auth/src/services/twoFA.service.ts
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { authConfig } from '../config';
import { prisma } from '@nutrition/database';

export class TwoFAService {
  static generateSecret(email: string): speakeasy.GeneratedSecret {
    return speakeasy.generateSecret({
      name: `${authConfig.twoFA.appName} (${email})`,
      length: 32,
    });
  }

  static async generateQRCode(secret: speakeasy.GeneratedSecret): Promise<string> {
    return QRCode.toDataURL(secret.otpauth_url!);
  }

  static verifyToken(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: authConfig.twoFA.window,
    });
  }

  static async enableTwoFA(userId: string, secret: string): Promise<string[]> {
    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      Math.random().toString(36).substring(2, 10).toUpperCase()
    );

    // Hash backup codes
    const hashedCodes = await Promise.all(
      backupCodes.map(code => bcrypt.hash(code, 10))
    );

    // Update user
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFASecret: secret,
        twoFAEnabled: true,
        twoFABackupCodes: hashedCodes,
      },
    });

    return backupCodes;
  }

  static async disableTwoFA(userId: string): Promise<void> {
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFASecret: null,
        twoFAEnabled: false,
        twoFABackupCodes: [],
      },
    });
  }

  static async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { twoFABackupCodes: true },
    });

    if (!user || !user.twoFABackupCodes) {
      return false;
    }

    // Check each backup code
    for (let i = 0; i < user.twoFABackupCodes.length; i++) {
      const isValid = await bcrypt.compare(code, user.twoFABackupCodes[i]);
      if (isValid) {
        // Remove used backup code
        const newCodes = [...user.twoFABackupCodes];
        newCodes.splice(i, 1);

        await prisma.user.update({
          where: { id: userId },
          data: { twoFABackupCodes: newCodes },
        });

        return true;
      }
    }

    return false;
  }
}
```

### Day 3-4: Auth Controllers & Middleware

#### 1. Auth Controller Implementation
```typescript
// services/auth/src/controllers/auth.controller.ts
import { Request, Response, NextFunction } from 'express';
import { prisma } from '@nutrition/database';
import { JWTService } from '../services/jwt.service';
import { PasswordService } from '../services/password.service';
import { TwoFAService } from '../services/twoFA.service';
import { EmailService } from '../services/email.service';
import { RegisterDTO, LoginDTO } from '../types/auth.types';
import { validateRegister, validateLogin } from '../validators/auth.validator';
import { AppError } from '../utils/errors';
import { auditLog } from '../utils/audit';

export class AuthController {
  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const body: RegisterDTO = req.body;

      // Validate input
      const validation = validateRegister(body);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      // Check if user exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { email: body.email },
            { phone: body.phone || undefined },
          ],
        },
      });

      if (existingUser) {
        throw new AppError('User already exists', 409);
      }

      // Validate password strength
      const passwordValidation = PasswordService.validateStrength(body.password);
      if (!passwordValidation.valid) {
        throw new AppError('Weak password', 400, passwordValidation.errors);
      }

      // Hash password
      const passwordHash = await PasswordService.hash(body.password);

      // Create user in transaction
      const user = await prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: {
            email: body.email,
            phone: body.phone,
            passwordHash,
            profile: {
              create: {
                firstName: body.firstName,
                lastName: body.lastName,
              },
            },
          },
          include: {
            profile: true,
          },
        });

        // Create audit log
        await auditLog({
          userId: newUser.id,
          action: 'REGISTER',
          entity: 'user',
          entityId: newUser.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        });

        return newUser;
      });

      // Send verification email
      const verificationToken = await EmailService.sendVerificationEmail(
        user.email,
        user.profile!.firstName
      );

      // Generate tokens
      const tokens = await JWTService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful. Please verify your email.',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.profile!.firstName,
            lastName: user.profile!.lastName,
            emailVerified: user.emailVerified,
          },
          tokens,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const body: LoginDTO = req.body;

      // Validate input
      const validation = validateLogin(body);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      // Find user
      const user = await prisma.user.findUnique({
        where: { email: body.email },
        include: {
          profile: true,
        },
      });

      if (!user) {
        throw new AppError('Invalid credentials', 401);
      }

      // Verify password
      const isValidPassword = await PasswordService.compare(
        body.password,
        user.passwordHash
      );

      if (!isValidPassword) {
        // Log failed attempt
        await auditLog({
          userId: user.id,
          action: 'LOGIN_FAILED',
          entity: 'user',
          entityId: user.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        });

        throw new AppError('Invalid credentials', 401);
      }

      // Check if 2FA is enabled
      if (user.twoFAEnabled) {
        if (!body.twoFactorCode) {
          return res.status(200).json({
            success: true,
            message: 'Two-factor authentication required',
            data: {
              requiresTwoFactor: true,
              userId: user.id,
            },
          });
        }

        // Verify 2FA code
        const isValid2FA = TwoFAService.verifyToken(
          user.twoFASecret!,
          body.twoFactorCode
        );

        if (!isValid2FA) {
          // Check backup code
          const isValidBackup = await TwoFAService.verifyBackupCode(
            user.id,
            body.twoFactorCode
          );

          if (!isValidBackup) {
            throw new AppError('Invalid two-factor code', 401);
          }
        }
      }

      // Update last login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });

      // Generate tokens
      const tokens = await JWTService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      // Log successful login
      await auditLog({
        userId: user.id,
        action: 'LOGIN',
        entity: 'user',
        entityId: user.id,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.profile!.firstName,
            lastName: user.profile!.lastName,
            emailVerified: user.emailVerified,
            twoFAEnabled: user.twoFAEnabled,
          },
          tokens,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async logout(req: Request, res: Response, next: NextFunction) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      const { userId, sessionId } = req.user!;

      if (token) {
        await JWTService.revokeToken(token, sessionId);
      }

      // Log logout
      await auditLog({
        userId,
        action: 'LOGOUT',
        entity: 'user',
        entityId: userId,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      res.json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      next(error);
    }
  }

  static async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw new AppError('Refresh token required', 400);
      }

      const tokens = await JWTService.refreshTokens(refreshToken);

      res.json({
        success: true,
        data: { tokens },
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.body;

      const userId = await EmailService.verifyEmailToken(token);
      if (!userId) {
        throw new AppError('Invalid or expired token', 400);
      }

      await prisma.user.update({
        where: { id: userId },
        data: { emailVerified: true },
      });

      res.json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async enable2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password } = req.body;

      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const isValidPassword = await PasswordService.compare(
        password,
        user.passwordHash
      );

      if (!isValidPassword) {
        throw new AppError('Invalid password', 401);
      }

      // Generate secret
      const secret = TwoFAService.generateSecret(user.email);
      const qrCode = await TwoFAService.generateQRCode(secret);

      // Store secret temporarily
      await redisClient.setex(
        `2fa_setup:${userId}`,
        600, // 10 minutes
        secret.base32
      );

      res.json({
        success: true,
        data: {
          secret: secret.base32,
          qrCode,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async confirm2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { token } = req.body;

      // Get temporary secret
      const secret = await redisClient.get(`2fa_setup:${userId}`);
      if (!secret) {
        throw new AppError('2FA setup expired', 400);
      }

      // Verify token
      const isValid = TwoFAService.verifyToken(secret, token);
      if (!isValid) {
        throw new AppError('Invalid token', 400);
      }

      // Enable 2FA and get backup codes
      const backupCodes = await TwoFAService.enableTwoFA(userId, secret);

      // Clean up temporary secret
      await redisClient.del(`2fa_setup:${userId}`);

      res.json({
        success: true,
        message: '2FA enabled successfully',
        data: {
          backupCodes,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async disable2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password, token } = req.body;

      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const isValidPassword = await PasswordService.compare(
        password,
        user.passwordHash
      );

      if (!isValidPassword) {
        throw new AppError('Invalid password', 401);
      }

      // Verify 2FA token
      if (user.twoFAEnabled && user.twoFASecret) {
        const isValid = TwoFAService.verifyToken(user.twoFASecret, token);
        if (!isValid) {
          throw new AppError('Invalid 2FA token', 401);
        }
      }

      // Disable 2FA
      await TwoFAService.disableTwoFA(userId);

      res.json({
        success: true,
        message: '2FA disabled successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body;

      const user = await prisma.user.findUnique({
        where: { email },
        include: { profile: true },
      });

      if (!user) {
        // Don't reveal if user exists
        return res.json({
          success: true,
          message: 'If the email exists, a reset link has been sent',
        });
      }

      // Generate reset token
      const resetToken = await PasswordService.generateResetToken(user.id);

      // Send reset email
      await EmailService.sendPasswordResetEmail(
        user.email,
        user.profile!.firstName,
        resetToken
      );

      res.json({
        success: true,
        message: 'If the email exists, a reset link has been sent',
      });
    } catch (error) {
      next(error);
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { token, password } = req.body;

      // Verify token
      const userId = await PasswordService.verifyResetToken(token);
      if (!userId) {
        throw new AppError('Invalid or expired token', 400);
      }

      // Validate password
      const passwordValidation = PasswordService.validateStrength(password);
      if (!passwordValidation.valid) {
        throw new AppError('Weak password', 400, passwordValidation.errors);
      }

      // Hash and update password
      const passwordHash = await PasswordService.hash(password);
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash },
      });

      // Revoke all tokens
      await JWTService.revokeAllUserTokens(userId);

      res.json({
        success: true,
        message: 'Password reset successful',
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Auth Middleware
```typescript
// services/auth/src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { JWTService } from '../services/jwt.service';
import { AppError } from '../utils/errors';
import { UserRole } from '../types/auth.types';

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        role: UserRole;
        sessionId?: string;
      };
    }
  }
}

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError('No token provided', 401);
    }

    const token = authHeader.split(' ')[1];
    const payload = await JWTService.verifyAccessToken(token);

    req.user = payload;
    next();
  } catch (error) {
    next(new AppError('Invalid token', 401));
  }
};

export const authorize = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Unauthorized', 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(new AppError('Forbidden', 403));
    }

    next();
  };
};

export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    const token = authHeader.split(' ')[1];
    const payload = await JWTService.verifyAccessToken(token);

    req.user = payload;
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};
```

### Day 5-7: Email Service & Templates

#### 1. Email Service Implementation
```typescript
// services/auth/src/services/email.service.ts
import nodemailer from 'nodemailer';
import mjml2html from 'mjml';
import { redisClient } from '../utils/redis';
import { authConfig } from '../config';
import crypto from 'crypto';

export class EmailService {
  private static transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  private static readonly VERIFICATION_PREFIX = 'email_verify:';
  private static readonly VERIFICATION_EXPIRY = 24 * 60 * 60; // 24 hours

  static async sendVerificationEmail(
    email: string,
    firstName: string
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Store token with user email
    await redisClient.setex(
      `${this.VERIFICATION_PREFIX}${hashedToken}`,
      this.VERIFICATION_EXPIRY,
      email
    );

    const verificationUrl = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Verify Your Email</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
          <mj-attributes>
            <mj-all font-family="Inter, Arial, sans-serif" />
            <mj-text font-size="16px" color="#333333" line-height="24px" />
            <mj-section background-color="#f4f4f4" />
          </mj-attributes>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="28px" font-weight="700" color="#1a1a1a" align="center">
                Welcome to Nutrition Platform!
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Hi ${firstName},
              </mj-text>
              <mj-text>
                Thank you for signing up! Please verify your email address to get started on your wellness journey.
              </mj-text>
              <mj-spacer height="30px" />
              <mj-button 
                background-color="#10b981" 
                color="#ffffff" 
                font-size="16px" 
                font-weight="600"
                padding="15px 30px"
                border-radius="6px"
                href="${verificationUrl}"
              >
                Verify Email Address
              </mj-button>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                Or copy and paste this link into your browser:
              </mj-text>
              <mj-text font-size="14px" color="#10b981">
                ${verificationUrl}
              </mj-text>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                This link will expire in 24 hours. If you didn't create an account, you can safely ignore this email.
              </mj-text>
            </mj-column>
          </mj-section>
          <mj-section padding="20px">
            <mj-column>
              <mj-text align="center" font-size="14px" color="#666666">
                © 2024 Nutrition Platform. All rights reserved.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Verify Your Email - Nutrition Platform',
      html,
    });

    return token;
  }

  static async verifyEmailToken(token: string): Promise<string | null> {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const email = await redisClient.get(`${this.VERIFICATION_PREFIX}${hashedToken}`);

    if (!email) {
      return null;
    }

    // Delete token after verification
    await redisClient.del(`${this.VERIFICATION_PREFIX}${hashedToken}`);
    return email;
  }

  static async sendPasswordResetEmail(
    email: string,
    firstName: string,
    resetToken: string
  ): Promise<void> {
    const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}`;

    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Reset Your Password</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
          <mj-attributes>
            <mj-all font-family="Inter, Arial, sans-serif" />
            <mj-text font-size="16px" color="#333333" line-height="24px" />
            <mj-section background-color="#f4f4f4" />
          </mj-attributes>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="28px" font-weight="700" color="#1a1a1a" align="center">
                Reset Your Password
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Hi ${firstName},
              </mj-text>
              <mj-text>
                We received a request to reset your password. Click the button below to create a new password.
              </mj-text>
              <mj-spacer height="30px" />
              <mj-button 
                background-color="#10b981" 
                color="#ffffff" 
                font-size="16px" 
                font-weight="600"
                padding="15px 30px"
                border-radius="6px"
                href="${resetUrl}"
              >
                Reset Password
              </mj-button>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text font-size="14px" color="#dc2626" font-weight="600">
                Security Tip: Never share your password with anyone, including our support team.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Reset Your Password - Nutrition Platform',
      html,
    });
  }

  static async sendWelcomeEmail(
    email: string,
    firstName: string
  ): Promise<void> {
    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Welcome to Your Wellness Journey</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="32px" font-weight="700" color="#1a1a1a" align="center">
                Welcome, ${firstName}! 🌱
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text font-size="18px" align="center" color="#666666">
                Your journey to better health starts now
              </mj-text>
              <mj-spacer height="40px" />
              <mj-text>
                We're thrilled to have you join our community! Here's what you can do next:
              </mj-text>
              <mj-spacer height="20px" />
              
              <!-- Getting Started Steps -->
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    🎯 1. Take the Health Assessment Quiz
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    Get personalized recommendations based on your health goals
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/quiz/health-assessment"
                  >
                    Start Quiz
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="15px" />
              
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    📅 2. Book Your Free Discovery Call
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    20-minute consultation to discuss your wellness goals
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/book-consultation"
                  >
                    Book Now
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="15px" />
              
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    📚 3. Explore Our Resources
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    Free guides, meal plans, and health tips
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/resources"
                  >
                    Browse Resources
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="40px" />
              
              <mj-text align="center" font-size="14px" color="#666666">
                Questions? Reply to this email or reach out to us at support@nutritionplatform.com
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Welcome to Your Wellness Journey! 🌱',
      html,
    });
  }

  static async send2FAEmail(
    email: string,
    firstName: string,
    code: string
  ): Promise<void> {
    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Your Login Code</mj-title>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="24px" font-weight="700" align="center">
                Your Login Code
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>Hi ${firstName},</mj-text>
              <mj-text>
                Here's your temporary login code:
              </mj-text>
              <mj-spacer height="20px" />
              <mj-wrapper background-color="#f8fafc" padding="20px" border-radius="6px">
                <mj-column>
                  <mj-text font-size="32px" font-weight="700" align="center" letter-spacing="8px">
                    ${code}
                  </mj-text>
                </mj-column>
              </mj-wrapper>
              <mj-spacer height="20px" />
              <mj-text font-size="14px" color="#666666">
                This code will expire in 5 minutes. If you didn't request this, please ignore this email.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: `Your Login Code: ${code}`,
      html,
    });
  }
}
```

## Week 3: User Service & Profile Management

### Day 1-2: User Service Setup

#### 1. User Service Structure
```typescript
// services/user/src/index.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { errorHandler } from './middleware/error.middleware';
import { requestLogger } from './middleware/logger.middleware';
import { rateLimiter } from './middleware/rateLimit.middleware';
import userRoutes from './routes/user.routes';
import profileRoutes from './routes/profile.routes';
import documentRoutes from './routes/document.routes';

const app = express();
const PORT = process.env.USER_SERVICE_PORT || 4002;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);
app.use(rateLimiter);

// Routes
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/profiles', profileRoutes);
app.use('/api/v1/documents', documentRoutes);

// Error handling
app.use(errorHandler);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'user-service' });
});

app.listen(PORT, () => {
  console.log(`User Service running on port ${PORT}`);
});
```

#### 2. User Controller
```typescript
// services/user/src/controllers/user.controller.ts
import { Request, Response, NextFunction } from 'express';
import { prisma } from '@nutrition/database';
import { UserService } from '../services/user.service';
import { ProfileService } from '../services/profile.service';
import { AppError } from '../utils/errors';
import { uploadToStorage } from '../utils/storage';

export class UserController {
  static async getProfile(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const profile = await ProfileService.getFullProfile(userId);

      if (!profile) {
        throw new AppError('Profile not found', 404);
      }

      res.json({
        success: true,
        data: profile,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateProfile(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const updates = req.body;

      // Validate updates
      const validation = ProfileService.validateProfileUpdate(updates);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      const updatedProfile = await ProfileService.updateProfile(userId, updates);

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: updatedProfile,
      });
    } catch (error) {
      next(error);
    }
  }

  static async uploadAvatar(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const file = req.file;

      if (!file) {
        throw new AppError('No file uploaded', 400);
      }

      // Validate file
      const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid file type', 400);
      }

      if (file.size > 5 * 1024 * 1024) { // 5MB
        throw new AppError('File too large', 400);
      }

      // Process and upload image
      const avatarUrl = await ProfileService.updateAvatar(userId, file);

      res.json({
        success: true,
        message: 'Avatar updated successfully',
        data: { avatarUrl },
      });
    } catch (error) {
      next(error);
    }
  }

  static async getMedicalHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const history = await UserService.getMedicalHistory(userId);

      res.json({
        success: true,
        data: history,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateMedicalHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const medicalData = req.body;

      const updated = await UserService.updateMedicalHistory(userId, medicalData);

      res.json({
        success: true,
        message: 'Medical history updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getHealthMetrics(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { startDate, endDate } = req.query;

      const metrics = await UserService.getHealthMetrics(
        userId,
        startDate as string,
        endDate as string
      );

      res.json({
        success: true,
        data: metrics,
      });
    } catch (error) {
      next(error);
    }
  }

  static async addHealthMetric(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const metricData = req.body;

      const metric = await UserService.addHealthMetric(userId, metricData);

      res.json({
        success: true,
        message: 'Health metric added successfully',
        data: metric,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const preferences = await UserService.getPreferences(userId);

      res.json({
        success: true,
        data: preferences,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updatePreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const preferences = req.body;

      const updated = await UserService.updatePreferences(userId, preferences);

      res.json({
        success: true,
        message: 'Preferences updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteAccount(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password, reason } = req.body;

      // Verify password
      const isValid = await UserService.verifyPassword(userId, password);
      if (!isValid) {
        throw new AppError('Invalid password', 401);
      }

      // Schedule account deletion
      await UserService.scheduleAccountDeletion(userId, reason);

      res.json({
        success: true,
        message: 'Account deletion scheduled. You have 30 days to cancel this request.',
      });
    } catch (error) {
      next(error);
    }
  }

  static async exportUserData(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      // Generate export
      const exportUrl = await UserService.exportUserData(userId);

      res.json({
        success: true,
        message: 'Your data export is ready',
        data: { downloadUrl: exportUrl },
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 3. Profile Service
```typescript
// services/user/src/services/profile.service.ts
import { prisma } from '@nutrition/database';
import sharp from 'sharp';
import { uploadToStorage, deleteFromStorage } from '../utils/storage';
import { calculateBMI, calculateBMR } from '../utils/health.calculations';

export class ProfileService {
  static async getFullProfile(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        profile: true,
        journeys: {
          include: {
            program: true,
          },
          orderBy: {
            startDate: 'desc',
          },
          take: 1,
        },
        consultations: {
          where: {
            status: 'COMPLETED',
          },
          orderBy: {
            completedAt: 'desc',
          },
          take: 5,
        },
      },
    });

    if (!user) {
      return null;
    }

    // Calculate additional metrics
    const metrics = user.profile
      ? {
          bmi: calculateBMI(user.profile.weight, user.profile.height),
          bmr: calculateBMR(
            user.profile.weight,
            user.profile.height,
            user.profile.dateOfBirth,
            user.profile.gender
          ),
        }
      : null;

    return {
      ...user,
      metrics,
    };
  }

  static validateProfileUpdate(data: any) {
    const errors: string[] = [];

    if (data.height && (data.height < 50 || data.height > 300)) {
      errors.push('Height must be between 50 and 300 cm');
    }

    if (data.weight && (data.weight < 20 || data.weight > 500)) {
      errors.push('Weight must be between 20 and 500 kg');
    }

    if (data.dateOfBirth) {
      const age = new Date().getFullYear() - new Date(data.dateOfBirth).getFullYear();
      if (age < 13 || age > 120) {
        errors.push('Age must be between 13 and 120 years');
      }
    }

    if (data.phone && !/^[+]?[0-9]{10,15}$/.test(data.phone)) {
      errors.push('Invalid phone number format');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async updateProfile(userId: string, updates: any) {
    const { allergies, medications, ...profileData } = updates;

    const updatedProfile = await prisma.userProfile.update({
      where: { userId },
      data: {
        ...profileData,
        allergies: allergies ? { set: allergies } : undefined,
        medications: medications ? { set: medications } : undefined,
      },
    });

    // Update phone in user table if provided
    if (updates.phone) {
      await prisma.user.update({
        where: { id: userId },
        data: { phone: updates.phone },
      });
    }

    return updatedProfile;
  }

  static async updateAvatar(userId: string, file: Express.Multer.File) {
    // Get current avatar to delete later
    const profile = await prisma.userProfile.findUnique({
      where: { userId },
      select: { avatar: true },
    });

    // Process image
    const processedImage = await sharp(file.buffer)
      .resize(400, 400, {
        fit: 'cover',
        position: 'center',
      })
      .jpeg({ quality: 90 })
      .toBuffer();

    // Upload to storage
    const filename = `avatars/${userId}-${Date.now()}.jpg`;
    const avatarUrl = await uploadToStorage(processedImage, filename, 'image/jpeg');

    // Update profile
    await prisma.userProfile.update({
      where: { userId },
      data: { avatar: avatarUrl },
    });

    // Delete old avatar if exists
    if (profile?.avatar) {
      await deleteFromStorage(profile.avatar).catch(console.error);
    }

    return avatarUrl;
  }

  static async createInitialProfile(userId: string, data: any) {
    return prisma.userProfile.create({
      data: {
        userId,
        firstName: data.firstName,
        lastName: data.lastName,
        ...data,
      },
    });
  }
}
```

### Day 3-4: Document Management

#### 1. Document Controller
```typescript
// services/user/src/controllers/document.controller.ts
import { Request, Response, NextFunction } from 'express';
import { DocumentService } from '../services/document.service';
import { AppError } from '../utils/errors';

export class DocumentController {
  static async uploadDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { type, title, description } = req.body;
      const file = req.file;

      if (!file) {
        throw new AppError('No file uploaded', 400);
      }

      // Validate file type
      const allowedTypes = [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      ];

      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid file type', 400);
      }

      // File size limit: 10MB
      if (file.size > 10 * 1024 * 1024) {
        throw new AppError('File too large (max 10MB)', 400);
      }

      const document = await DocumentService.uploadDocument(userId, {
        type,
        title,
        description,
        file,
      });

      res.status(201).json({
        success: true,
        message: 'Document uploaded successfully',
        data: document,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocuments(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { type, page = 1, limit = 20 } = req.query;

      const documents = await DocumentService.getUserDocuments(userId, {
        type: type as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: documents,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const document = await DocumentService.getDocument(id, userId);

      if (!document) {
        throw new AppError('Document not found', 404);
      }

      res.json({
        success: true,
        data: document,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocumentUrl(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const url = await DocumentService.getSignedUrl(id, userId);

      res.json({
        success: true,
        data: { url },
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      await DocumentService.deleteDocument(id, userId);

      res.json({
        success: true,
        message: 'Document deleted successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async archiveDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      await DocumentService.archiveDocument(id, userId);

      res.json({
        success: true,
        message: 'Document archived successfully',
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Document Service
```typescript
// services/user/src/services/document.service.ts
import { prisma } from '@nutrition/database';
import { uploadToStorage, deleteFromStorage, getSignedUrl } from '../utils/storage';
import crypto from 'crypto';
import { scanFile } from '../utils/antivirus';

interface UploadDocumentDto {
  type: string;
  title: string;
  description?: string;
  file: Express.Multer.File;
}

export class DocumentService {
  static async uploadDocument(userId: string, data: UploadDocumentDto) {
    // Scan file for viruses
    const isSafe = await scanFile(data.file.buffer);
    if (!isSafe) {
      throw new Error('File failed security scan');
    }

    // Generate unique filename
    const fileExt = data.file.originalname.split('.').pop();
    const filename = `documents/${userId}/${crypto.randomBytes(16).toString('hex')}.${fileExt}`;

    // Upload to storage
    const fileUrl = await uploadToStorage(
      data.file.buffer,
      filename,
      data.file.mimetype
    );

    // Create document record
    const document = await prisma.document.create({
      data: {
        userId,
        type: data.type,
        title: data.title,
        description: data.description,
        fileUrl,
        fileSize: data.file.size,
        mimeType: data.file.mimetype,
      },
    });

    return document;
  }

  static async getUserDocuments(
    userId: string,
    options: { type?: string; page: number; limit: number }
  ) {
    const where = {
      userId,
      isArchived: false,
      ...(options.type && { type: options.type }),
    };

    const [documents, total] = await Promise.all([
      prisma.document.findMany({
        where,
        orderBy: { uploadedAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
      }),
      prisma.document.count({ where }),
    ]);

    return {
      documents,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getDocument(documentId: string, userId: string) {
    return prisma.document.findFirst({
      where: {
        id: documentId,
        userId,
      },
    });
  }

  static async getSignedUrl(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    return getSignedUrl(document.fileUrl, 3600); // 1 hour expiry
  }

  static async deleteDocument(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    // Delete from storage
    await deleteFromStorage(document.fileUrl);

    // Delete from database
    await prisma.document.delete({
      where: { id: documentId },
    });
  }

  static async archiveDocument(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    await prisma.document.update({
      where: { id: documentId },
      data: { isArchived: true },
    });
  }

  static async getDocumentsByType(userId: string, type: string) {
    return prisma.document.findMany({
      where: {
        userId,
        type,
        isArchived: false,
      },
      orderBy: { uploadedAt: 'desc' },
    });
  }
}
```

### Day 3-4: Consultation Booking Service

#### 1. Consultation Controller
```typescript
// services/consultation/src/controllers/consultation.controller.ts
import { Request, Response, NextFunction } from 'express';
import { ConsultationService } from '../services/consultation.service';
import { CalendarService } from '../services/calendar.service';
import { AppError } from '../utils/errors';

export class ConsultationController {
  static async getAvailableSlots(req: Request, res: Response, next: NextFunction) {
    try {
      const { nutritionistId, date, timezone = 'Asia/Kolkata' } = req.query;

      if (!nutritionistId || !date) {
        throw new AppError('Nutritionist ID and date are required', 400);
      }

      const slots = await CalendarService.getAvailableSlots(
        nutritionistId as string,
        new Date(date as string),
        timezone as string
      );

      res.json({
        success: true,
        data: slots,
      });
    } catch (error) {
      next(error);
    }
  }

  static async bookConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const {
        nutritionistId,
        programId,
        scheduledAt,
        duration = 60,
        notes,
        timezone = 'Asia/Kolkata',
      } = req.body;

      // Validate slot availability
      const isAvailable = await CalendarService.checkSlotAvailability(
        nutritionistId,
        new Date(scheduledAt),
        duration
      );

      if (!isAvailable) {
        throw new AppError('Selected time slot is not available', 400);
      }

      const consultation = await ConsultationService.bookConsultation({
        userId,
        nutritionistId,
        programId,
        scheduledAt: new Date(scheduledAt),
        duration,
        notes,
        timezone,
      });

      res.status(201).json({
        success: true,
        message: 'Consultation booked successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUserConsultations(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { status, page = 1, limit = 10 } = req.query;

      const consultations = await ConsultationService.getUserConsultations(userId, {
        status: status as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: consultations,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const consultation = await ConsultationService.getConsultation(id, userId);

      if (!consultation) {
        throw new AppError('Consultation not found', 404);
      }

      res.json({
        success: true,
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async rescheduleConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { scheduledAt, reason } = req.body;

      const consultation = await ConsultationService.rescheduleConsultation(
        id,
        userId,
        new Date(scheduledAt),
        reason
      );

      res.json({
        success: true,
        message: 'Consultation rescheduled successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async cancelConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { reason } = req.body;

      await ConsultationService.cancelConsultation(id, userId, reason);

      res.json({
        success: true,
        message: 'Consultation cancelled successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async joinConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const meetingInfo = await ConsultationService.getMeetingInfo(id, userId);

      res.json({
        success: true,
        data: meetingInfo,
      });
    } catch (error) {
      next(error);
    }
  }

  static async completeConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { notes, prescription, followUpDate } = req.body;

      // Only nutritionist can complete consultation
      const consultation = await ConsultationService.completeConsultation(id, {
        nutritionistId: userId,
        notes,
        prescription,
        followUpDate,
      });

      res.json({
        success: true,
        message: 'Consultation completed successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUpcomingReminders(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const reminders = await ConsultationService.getUpcomingReminders(userId);

      res.json({
        success: true,
        data: reminders,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Consultation Service
```typescript
// services/consultation/src/services/consultation.service.ts
import { prisma } from '@nutrition/database';
import { VideoService } from './video.service';
import { NotificationService } from './notification.service';
import { CalendarService } from './calendar.service';
import { PaymentService } from './payment.service';
import { addMinutes, subHours, isAfter, isBefore } from 'date-fns';

interface BookConsultationDto {
  userId: string;
  nutritionistId: string;
  programId?: string;
  scheduledAt: Date;
  duration: number;
  notes?: string;
  timezone: string;
}

export class ConsultationService {
  static async bookConsultation(data: BookConsultationDto) {
    // Start transaction
    return prisma.$transaction(async (tx) => {
      // Check for conflicts
      const conflicts = await tx.consultation.findMany({
        where: {
          OR: [
            { userId: data.userId },
            { nutritionistId: data.nutritionistId },
          ],
          scheduledAt: {
            gte: data.scheduledAt,
            lt: addMinutes(data.scheduledAt, data.duration),
          },
          status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
        },
      });

      if (conflicts.length > 0) {
        throw new Error('Time slot conflict detected');
      }

      // Get nutritionist details for pricing
      const nutritionist = await tx.nutritionistProfile.findUnique({
        where: { userId: data.nutritionistId },
      });

      if (!nutritionist) {
        throw new Error('Nutritionist not found');
      }

      // Create consultation
      const consultation = await tx.consultation.create({
        data: {
          userId: data.userId,
          nutritionistId: data.nutritionistId,
          programId: data.programId,
          scheduledAt: data.scheduledAt,
          duration: data.duration,
          status: 'SCHEDULED',
          notes: data.notes,
        },
        include: {
          user: {
            include: { profile: true },
          },
          nutritionist: {
            include: { profile: true },
          },
        },
      });

      // Create video meeting
      const meeting = await VideoService.createMeeting({
        consultationId: consultation.id,
        topic: `Consultation with ${consultation.nutritionist.profile?.firstName}`,
        startTime: data.scheduledAt,
        duration: data.duration,
        timezone: data.timezone,
      });

      // Update consultation with meeting details
      await tx.consultation.update({
        where: { id: consultation.id },
        data: {
          meetingLink: meeting.joinUrl,
          meetingId: meeting.id,
        },
      });

      // Create calendar events
      await CalendarService.createEvents({
        consultation,
        userTimezone: data.timezone,
      });

      // Schedule reminders
      await this.scheduleReminders(consultation.id, data.scheduledAt);

      // Send confirmation emails
      await NotificationService.sendConsultationBooked(consultation);

      return consultation;
    });
  }

  static async getUserConsultations(userId: string, options: {
    status?: string;
    page: number;
    limit: number;
  }) {
    const where: any = { userId };

    if (options.status) {
      where.status = options.status;
    }

    const [consultations, total] = await Promise.all([
      prisma.consultation.findMany({
        where,
        orderBy: { scheduledAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          nutritionist: {
            include: {
              user: true,
              profile: true,
            },
          },
          program: true,
          payment: true,
        },
      }),
      prisma.consultation.count({ where }),
    ]);

    return {
      consultations,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getConsultation(consultationId: string, userId: string) {
    return prisma.consultation.findFirst({
      where: {
        id: consultationId,
        OR: [
          { userId },
          { nutritionistId: userId },
        ],
      },
      include: {
        user: {
          include: { profile: true },
        },
        nutritionist: {
          include: {
            user: true,
            profile: true,
          },
        },
        program: true,
        payment: true,
        reminders: true,
      },
    });
  }

  static async rescheduleConsultation(
    consultationId: string,
    userId: string,
    newScheduledAt: Date,
    reason: string
  ) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (consultation.status !== 'SCHEDULED') {
      throw new Error('Only scheduled consultations can be rescheduled');
    }

    // Check if within reschedule window (24 hours before)
    const rescheduleDeadline = subHours(consultation.scheduledAt, 24);
    if (isAfter(new Date(), rescheduleDeadline)) {
      throw new Error('Cannot reschedule within 24 hours of appointment');
    }

    // Check new slot availability
    const isAvailable = await CalendarService.checkSlotAvailability(
      consultation.nutritionistId,
      newScheduledAt,
      consultation.duration
    );

    if (!isAvailable) {
      throw new Error('New time slot is not available');
    }

    // Update consultation
    const updated = await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        scheduledAt: newScheduledAt,
        updatedAt: new Date(),
      },
    });

    // Update video meeting
    if (consultation.meetingId) {
      await VideoService.updateMeeting(consultation.meetingId, {
        startTime: newScheduledAt,
      });
    }

    // Cancel old reminders and schedule new ones
    await this.cancelReminders(consultationId);
    await this.scheduleReminders(consultationId, newScheduledAt);

    // Update calendar events
    await CalendarService.updateEvents({
      consultation: updated,
      oldScheduledAt: consultation.scheduledAt,
    });

    // Send notifications
    await NotificationService.sendConsultationRescheduled(updated, reason);

    return updated;
  }

  static async cancelConsultation(
    consultationId: string,
    userId: string,
    reason: string
  ) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (!['SCHEDULED', 'IN_PROGRESS'].includes(consultation.status)) {
      throw new Error('Cannot cancel this consultation');
    }

    // Check cancellation policy
    const cancellationDeadline = subHours(consultation.scheduledAt, 4);
    const isLateCancellation = isAfter(new Date(), cancellationDeadline);

    // Update consultation
    await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        status: 'CANCELLED',
        cancelledAt: new Date(),
        cancellationReason: reason,
      },
    });

    // Cancel video meeting
    if (consultation.meetingId) {
      await VideoService.cancelMeeting(consultation.meetingId);
    }

    // Cancel reminders
    await this.cancelReminders(consultationId);

    // Process refund if applicable
    if (consultation.payment && !isLateCancellation) {
      await PaymentService.processRefund(consultation.payment.id, 'full');
    }

    // Send notifications
    await NotificationService.sendConsultationCancelled(consultation, reason);
  }

  static async getMeetingInfo(consultationId: string, userId: string) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    // Check if it's time to join (15 minutes before to 30 minutes after)
    const now = new Date();
    const joinWindowStart = subHours(consultation.scheduledAt, 0.25); // 15 minutes before
    const joinWindowEnd = addMinutes(consultation.scheduledAt, 30);

    if (isBefore(now, joinWindowStart) || isAfter(now, joinWindowEnd)) {
      throw new Error('Meeting room is not available at this time');
    }

    // Update status if needed
    if (consultation.status === 'SCHEDULED' && isAfter(now, consultation.scheduledAt)) {
      await prisma.consultation.update({
        where: { id: consultationId },
        data: { status: 'IN_PROGRESS' },
      });
    }

    return {
      meetingLink: consultation.meetingLink,
      meetingId: consultation.meetingId,
      hostLink: userId === consultation.nutritionistId 
        ? await VideoService.getHostLink(consultation.meetingId!) 
        : null,
    };
  }

  static async completeConsultation(consultationId: string, data: {
    nutritionistId: string;
    notes?: string;
    prescription?: any;
    followUpDate?: Date;
  }) {
    const consultation = await prisma.consultation.findFirst({
      where: {
        id: consultationId,
        nutritionistId: data.nutritionistId,
      },
    });

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (consultation.status !== 'IN_PROGRESS') {
      throw new Error('Consultation must be in progress to complete');
    }

    // Update consultation
    const updated = await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        status: 'COMPLETED',
        completedAt: new Date(),
        internalNotes: data.notes,
        prescription: data.prescription,
        followUpDate: data.followUpDate,
      },
      include: {
        user: {
          include: { profile: true },
        },
      },
    });

    // Generate prescription PDF if provided
    if (data.prescription) {
      const prescriptionUrl = await this.generatePrescriptionPDF(
        updated,
        data.prescription
      );

      await prisma.consultation.update({
        where: { id: consultationId },
        data: { prescriptionUrl },
      });
    }

    // Send follow-up email with notes
    await NotificationService.sendConsultationCompleted(updated);

    // Schedule follow-up reminder if date provided
    if (data.followUpDate) {
      await this.scheduleFollowUpReminder(consultationId, data.followUpDate);
    }

    return updated;
  }

  static async getUpcomingReminders(userId: string) {
    const upcoming = await prisma.consultation.findMany({
      where: {
        OR: [
          { userId },
          { nutritionistId: userId },
        ],
        status: 'SCHEDULED',
        scheduledAt: {
          gte: new Date(),
          lte: addMinutes(new Date(), 24 * 60), // Next 24 hours
        },
      },
      orderBy: { scheduledAt: 'asc' },
      include: {
        user: {
          include: { profile: true },
        },
        nutritionist: {
          include: { profile: true },
        },
      },
    });

    return upcoming;
  }

  private static async scheduleReminders(consultationId: string, scheduledAt: Date) {
    const reminderTimes = [
      { type: 'email', minutesBefore: 24 * 60 }, // 1 day before
      { type: 'email', minutesBefore: 60 }, // 1 hour before
      { type: 'sms', minutesBefore: 30 }, // 30 minutes before
      { type: 'whatsapp', minutesBefore: 15 }, // 15 minutes before
    ];

    const reminders = reminderTimes.map((reminder) => ({
      consultationId,
      type: reminder.type,
      scheduledAt: new Date(scheduledAt.getTime() - reminder.minutesBefore * 60 * 1000),
      status: 'pending',
    }));

    await prisma.consultationReminder.createMany({
      data: reminders,
    });
  }

  private static async cancelReminders(consultationId: string) {
    await prisma.consultationReminder.updateMany({
      where: {
        consultationId,
        status: 'pending',
      },
      data: {
        status: 'cancelled',
      },
    });
  }

  private static async scheduleFollowUpReminder(
    consultationId: string,
    followUpDate: Date
  ) {
    await prisma.consultationReminder.create({
      data: {
        consultationId,
        type: 'email',
        scheduledAt: subHours(followUpDate, 24),
        status: 'pending',
      },
    });
  }

  private static async generatePrescriptionPDF(consultation: any, prescription: any) {
    // This would integrate with a PDF generation service
    // For now, returning a placeholder
    return `prescriptions/${consultation.id}.pdf`;
  }
}
```

### Day 5-7: Calendar & Video Integration

#### 1. Calendar Service
```typescript
// services/consultation/src/services/calendar.service.ts
import { google } from 'googleapis';
import { prisma } from '@nutrition/database';
import { addMinutes, format, startOfDay, endOfDay } from 'date-fns';
import { utcToZonedTime, zonedTimeToUtc } from 'date-fns-tz';

export class CalendarService {
  private static oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URL
  );

  static async getAvailableSlots(
    nutritionistId: string,
    date: Date,
    timezone: string
  ) {
    // Get nutritionist availability
    const nutritionist = await prisma.nutritionistProfile.findUnique({
      where: { userId: nutritionistId },
      include: { user: true },
    });

    if (!nutritionist) {
      throw new Error('Nutritionist not found');
    }

    // Get working hours from availability
    const dayOfWeek = format(date, 'EEEE').toLowerCase();
    const workingHours = nutritionist.availability?.[dayOfWeek] || {
      start: '09:00',
      end: '17:00',
      breaks: [{ start: '13:00', end: '14:00' }],
    };

    // Get existing consultations for the day
    const dayStart = startOfDay(date);
    const dayEnd = endOfDay(date);

    const existingConsultations = await prisma.consultation.findMany({
      where: {
        nutritionistId,
        scheduledAt: {
          gte: dayStart,
          lte: dayEnd,
        },
        status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
      },
      select: {
        scheduledAt: true,
        duration: true,
      },
    });

    // Generate available slots
    const slots = this.generateTimeSlots(
      workingHours,
      existingConsultations,
      date,
      timezone
    );

    return slots;
  }

  static async checkSlotAvailability(
    nutritionistId: string,
    scheduledAt: Date,
    duration: number
  ): Promise<boolean> {
    const endTime = addMinutes(scheduledAt, duration);

    const conflicts = await prisma.consultation.count({
      where: {
        nutritionistId,
        status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
        OR: [
          {
            // New consultation starts during existing one
            scheduledAt: {
              lte: scheduledAt,
            },
            AND: {
              scheduledAt: {
                gt: new Date(scheduledAt.getTime() - duration * 60 * 1000),
              },
            },
          },
          {
            // New consultation ends during existing one
            scheduledAt: {
              lt: endTime,
              gte: scheduledAt,
            },
          },
        ],
      },
    });

    return conflicts === 0;
  }

  static async createEvents(data: {
    consultation: any;
    userTimezone: string;
  }) {
    const { consultation, userTimezone } = data;

    // Create calendar event for user
    if (consultation.user.googleCalendarConnected) {
      await this.createGoogleCalendarEvent({
        userId: consultation.userId,
        title: `Nutrition Consultation with ${consultation.nutritionist.profile?.firstName}`,
        description: `Meeting link: ${consultation.meetingLink}\n\nNotes: ${consultation.notes || 'N/A'}`,
        startTime: consultation.scheduledAt,
        endTime: addMinutes(consultation.scheduledAt, consultation.duration),
        timezone: userTimezone,
      });
    }

    // Create calendar event for nutritionist
    if (consultation.nutritionist.user.googleCalendarConnected) {
      await this.createGoogleCalendarEvent({
        userId: consultation.nutritionistId,
        title: `Consultation with ${consultation.user.profile?.firstName} ${consultation.user.profile?.lastName}`,
        description: `Meeting link: ${consultation.meetingLink}\n\nNotes: ${consultation.notes || 'N/A'}`,
        startTime: consultation.scheduledAt,
        endTime: addMinutes(consultation.scheduledAt, consultation.duration),
        timezone: 'Asia/Kolkata', // Nutritionist timezone
      });
    }
  }

  static async updateEvents(data: {
    consultation: any;
    oldScheduledAt: Date;
  }) {
    // This would update existing calendar events
    // Implementation depends on storing event IDs
  }

  private static generateTimeSlots(
    workingHours: any,
    existingConsultations: any[],
    date: Date,
    timezone: string
  ) {
    const slots: Array<{ time: Date; available: boolean }> = [];
    const slotDuration = 30; // 30-minute slots

    // Parse working hours
    const [startHour, startMinute] = workingHours.start.split(':').map(Number);
    const [endHour, endMinute] = workingHours.end.split(':').map(Number);

    let currentSlot = new Date(date);
    currentSlot.setHours(startHour, startMinute, 0, 0);

    const endTime = new Date(date);
    endTime.setHours(endHour, endMinute, 0, 0);

    while (currentSlot < endTime) {
      // Check if slot is during break time
      const isBreakTime = workingHours.breaks?.some((breakTime: any) => {
        const [breakStartHour, breakStartMinute] = breakTime.start.split(':').map(Number);
        const [breakEndHour, breakEndMinute] = breakTime.end.split(':').map(Number);

        const breakStart = new Date(date);
        breakStart.setHours(breakStartHour, breakStartMinute, 0, 0);

        const breakEnd = new Date(date);
        breakEnd.setHours(breakEndHour, breakEndMinute, 0, 0);

        return currentSlot >= breakStart && currentSlot < breakEnd;
      });

      // Check if slot conflicts with existing consultations
      const hasConflict = existingConsultations.some((consultation) => {
        const consultEnd = addMinutes(consultation.scheduledAt, consultation.duration);
        return currentSlot >= consultation.scheduledAt && currentSlot < consultEnd;
      });

      // Check if slot is in the past
      const isPast = currentSlot < new Date();

      slots.push({
        time: zonedTimeToUtc(currentSlot, timezone),
        available: !isBreakTime && !hasConflict && !isPast,
      });

      currentSlot = addMinutes(currentSlot, slotDuration);
    }

    return slots;
  }

  private static async createGoogleCalendarEvent(data: {
    userId: string;
    title: string;
    description: string;
    startTime: Date;
    endTime: Date;
    timezone: string;
  }) {
    try {
      // Get user's Google tokens
      const tokens = await this.getUserGoogleTokens(data.userId);
      if (!tokens) return;

      this.oauth2Client.setCredentials(tokens);
      const calendar = google.calendar({ version: 'v3', auth: this.oauth2Client });

      const event = {
        summary: data.title,
        description: data.description,
        start: {
          dateTime: data.startTime.toISOString(),
          timeZone: data.timezone,
        },
        end: {
          dateTime: data.endTime.toISOString(),
          timeZone: data.timezone,
        },
        reminders: {
          useDefault: false,
          overrides: [
            { method: 'email', minutes: 60 },
            { method: 'popup', minutes: 15 },
          ],
        },
      };

      await calendar.events.insert({
        calendarId: 'primary',
        requestBody: event,
      });
    } catch (error) {
      console.error('Failed to create Google Calendar event:', error);
    }
  }

  private static async getUserGoogleTokens(userId: string) {
    // This would fetch stored Google OAuth tokens from database
    // Implementation depends on OAuth flow implementation
    return null;
  }
}
```

#### 2. Video Service
```typescript
// services/consultation/src/services/video.service.ts
import axios from 'axios';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

interface CreateMeetingDto {
  consultationId: string;
  topic: string;
  startTime: Date;
  duration: number;
  timezone: string;
}

export class VideoService {
  private static readonly ZOOM_API_URL = 'https://api.zoom.us/v2';
  private static readonly JWT_SECRET = process.env.ZOOM_JWT_SECRET!;
  private static readonly JWT_KEY = process.env.ZOOM_JWT_KEY!;

  static async createMeeting(data: CreateMeetingDto) {
    const token = this.generateZoomJWT();

    try {
      const response = await axios.post(
        `${this.ZOOM_API_URL}/users/me/meetings`,
        {
          topic: data.topic,
          type: 2, // Scheduled meeting
          start_time: data.startTime.toISOString(),
          duration: data.duration,
          timezone: data.timezone,
          password: this.generateMeetingPassword(),
          settings: {
            host_video: true,
            participant_video: true,
            join_before_host: false,
            mute_upon_entry: true,
            watermark: false,
            use_pmi: false,
            approval_type: 0,
            audio: 'both',
            auto_recording: 'cloud',
            waiting_room: true,
          },
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return {
        id: response.data.id.toString(),
        joinUrl: response.data.join_url,
        startUrl: response.data.start_url,
        password: response.data.password,
      };
    } catch (error) {
      console.error('Failed to create Zoom meeting:', error);
      // Fallback to Jitsi Meet
      return this.createJitsiMeeting(data);
    }
  }

  static async updateMeeting(meetingId: string, updates: {
    startTime?: Date;
    duration?: number;
  }) {
    const token = this.generateZoomJWT();

    try {
      await axios.patch(
        `${this.ZOOM_API_URL}/meetings/${meetingId}`,
        {
          start_time: updates.startTime?.toISOString(),
          duration: updates.duration,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );
    } catch (error) {
      console.error('Failed to update Zoom meeting:', error);
    }
  }

  static async cancelMeeting(meetingId: string) {
    const token = this.generateZoomJWT();

    try {
      await axios.delete(
        `${this.ZOOM_API_URL}/meetings/${meetingId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
    } catch (error) {
      console.error('Failed to cancel Zoom meeting:', error);
    }
  }

  static async getHostLink(meetingId: string): Promise<string> {
    // For Zoom, the host link is stored separately
    // For Jitsi, we can generate it with moderator params
    if (meetingId.startsWith('jitsi_')) {
      const roomName = meetingId.replace('jitsi_', '');
      return `https://meet.jit.si/${roomName}#config.prejoinPageEnabled=false&userInfo.displayName=Nutritionist`;
    }

    // For Zoom, return the stored start URL
    return '';
  }

  private static createJitsiMeeting(data: CreateMeetingDto) {
    // Jitsi Meet doesn't require API calls for room creation
    const roomName = `nutrition_${data.consultationId}_${Date.now()}`;
    const joinUrl = `https://meet.jit.si/${roomName}`;

    return {
      id: `jitsi_${roomName}`,
      joinUrl,
      startUrl: joinUrl,
      password: '',
    };
  }

  private static generateZoomJWT(): string {
    const payload = {
      iss: this.JWT_KEY,
      exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour expiry
    };

    return jwt.sign(payload, this.JWT_SECRET);
  }

  private static generateMeetingPassword(): string {
    return crypto.randomBytes(4).toString('hex').substring(0, 6);
  }
}
```

## Week 5: Payment Integration & Security

### Day 1-3: Payment Service Implementation

#### 1. Payment Controller
```typescript
// services/payment/src/controllers/payment.controller.ts
import { Request, Response, NextFunction } from 'express';
import { PaymentService } from '../services/payment.service';
import { InvoiceService } from '../services/invoice.service';
import { AppError } from '../utils/errors';

export class PaymentController {
  static async createOrder(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { 
        amount, 
        currency = 'INR', 
        type, 
        referenceId,
        gateway = 'razorpay' 
      } = req.body;

      const order = await PaymentService.createOrder({
        userId,
        amount,
        currency,
        type,
        referenceId,
        gateway,
      });

      res.json({
        success: true,
        data: order,
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyPayment(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { 
        orderId, 
        paymentId, 
        signature,
        gateway = 'razorpay' 
      } = req.body;

      const payment = await PaymentService.verifyPayment({
        userId,
        orderId,
        paymentId,
        signature,
        gateway,
      });

      res.json({
        success: true,
        message: 'Payment verified successfully',
        data: payment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async handleWebhook(req: Request, res: Response, next: NextFunction) {
    try {
      const signature = req.headers['x-razorpay-signature'] as string;
      const gateway = req.params.gateway;

      await PaymentService.handleWebhook({
        gateway,
        signature,
        payload: req.body,
      });

      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  }

  static async getPaymentHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { status, page = 1, limit = 10 } = req.query;

      const payments = await PaymentService.getPaymentHistory(userId, {
        status: status as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: payments,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getInvoice(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;

      const invoice = await InvoiceService.getInvoice(paymentId, userId);

      res.json({
        success: true,
        data: invoice,
      });
    } catch (error) {
      next(error);
    }
  }

  static async downloadInvoice(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;

      const invoiceBuffer = await InvoiceService.generateInvoicePDF(
        paymentId,
        userId
      );

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="invoice-${paymentId}.pdf"`
      );
      res.send(invoiceBuffer);
    } catch (error) {
      next(error);
    }
  }

  static async initiateRefund(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;
      const { amount, reason } = req.body;

      const refund = await PaymentService.initiateRefund({
        paymentId,
        userId,
        amount,
        reason,
      });

      res.json({
        success: true,
        message: 'Refund initiated successfully',
        data: refund,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPaymentMethods(req: Request, res: Response, next: NextFunction) {
    try {
      const methods = await PaymentService.getAvailablePaymentMethods();

      res.json({
        success: true,
        data: methods,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Payment Service with Razorpay Integration
```typescript
// services/payment/src/services/payment.service.ts
import Razorpay from 'razorpay';
import crypto from 'crypto';
import { prisma } from '@nutrition/database';
import { PaymentGateway } from './gateways/payment.gateway';
import { RazorpayGateway } from './gateways/razorpay.gateway';
import { CashfreeGateway } from './gateways/cashfree.gateway';
import { generateInvoiceNumber } from '../utils/invoice.utils';

interface CreateOrderDto {
  userId: string;
  amount: number;
  currency: string;
  type: string;
  referenceId: string;
  gateway: string;
}

interface VerifyPaymentDto {
  userId: string;
  orderId: string;
  paymentId: string;
  signature: string;
  gateway: string;
}

export class PaymentService {
  private static gateways: Record<string, PaymentGateway> = {
    razorpay: new RazorpayGateway(),
    cashfree: new CashfreeGateway(),
  };

  static async createOrder(data: CreateOrderDto) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Create order in gateway
    const gatewayOrder = await gateway.createOrder({
      amount: data.amount,
      currency: data.currency,
      receipt: `order_${Date.now()}`,
      notes: {
        userId: data.userId,
        type: data.type,
        referenceId: data.referenceId,
      },
    });

    // Create payment record
    const payment = await prisma.payment.create({
      data: {
        userId: data.userId,
        amount: data.amount,
        currency: data.currency,
        status: 'PENDING',
        gateway: data.gateway,
        gatewayOrderId: gatewayOrder.id,
        metadata: {
          type: data.type,
          referenceId: data.referenceId,
        },
      },
    });

    return {
      paymentId: payment.id,
      orderId: gatewayOrder.id,
      amount: data.amount,
      currency: data.currency,
      gateway: data.gateway,
      gatewayData: gatewayOrder,
    };
  }

  static async verifyPayment(data: VerifyPaymentDto) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Get payment record
    const payment = await prisma.payment.findFirst({
      where: {
        userId: data.userId,
        gatewayOrderId: data.orderId,
        status: 'PENDING',
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    // Verify signature
    const isValid = await gateway.verifySignature({
      orderId: data.orderId,
      paymentId: data.paymentId,
      signature: data.signature,
    });

    if (!isValid) {
      throw new Error('Invalid payment signature');
    }

    // Update payment status
    const updatedPayment = await prisma.payment.update({
      where: { id: payment.id },
      data: {
        status: 'SUCCESS',
        gatewayPaymentId: data.paymentId,
        gatewaySignature: data.signature,
        invoiceNumber: generateInvoiceNumber(),
        updatedAt: new Date(),
      },
    });

    // Handle post-payment actions based on type
    await this.handlePostPaymentActions(updatedPayment);

    return updatedPayment;
  }

  static async handleWebhook(data: {
    gateway: string;
    signature: string;
    payload: any;
  }) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Verify webhook signature
    const isValid = await gateway.verifyWebhookSignature(
      data.payload,
      data.signature
    );

    if (!isValid) {
      throw new Error('Invalid webhook signature');
    }

    // Process webhook based on event type
    const event = gateway.parseWebhookEvent(data.payload);

    switch (event.type) {
      case 'payment.captured':
        await this.handlePaymentCaptured(event.data);
        break;
      case 'payment.failed':
        await this.handlePaymentFailed(event.data);
        break;
      case 'refund.processed':
        await this.handleRefundProcessed(event.data);
        break;
      default:
        console.log('Unhandled webhook event:', event.type);
    }
  }

  static async getPaymentHistory(userId: string, options: {
    status?: string;
    page: number;
    limit: number;
  }) {
    const where: any = { userId };

    if (options.status) {
      where.status = options.status;
    }

    const [payments, total] = await Promise.all([
      prisma.payment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          consultation: {
            include: {
              nutritionist: {
                include: { profile: true },
              },
            },
          },
          journey: {
            include: { program: true },
          },
        },
      }),
      prisma.payment.count({ where }),
    ]);

    return {
      payments,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async initiateRefund(data: {
    paymentId: string;
    userId: string;
    amount?: number;
    reason: string;
  }) {
    const payment = await prisma.payment.findFirst({
      where: {
        id: data.paymentId,
        userId: data.userId,
        status: 'SUCCESS',
      },
    });

    if (!payment) {
      throw new Error('Payment not found or not eligible for refund');
    }

    // Check if already refunded
    if (payment.refundId) {
      throw new Error('Payment already refunded');
    }

    const gateway = this.gateways[payment.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Initiate refund with gateway
    const refundAmount = data.amount || payment.amount;
    const refund = await gateway.initiateRefund({
      paymentId: payment.gatewayPaymentId!,
      amount: refundAmount,
      notes: {
        reason: data.reason,
      },
    });

    // Update payment record
    await prisma.payment.update({
      where: { id: payment.id },
      data: {
        refundId: refund.id,
        refundAmount: refundAmount,
        refundedAt: new Date(),
        status: refundAmount === payment.amount ? 'REFUNDED' : 'PARTIALLY_REFUNDED',
      },
    });

    return refund;
  }

  static async getAvailablePaymentMethods() {
    return [
      {
        id: 'upi',
        name: 'UPI',
        description: 'Pay using any UPI app',
        icon: 'upi-icon',
        enabled: true,
      },
      {
        id: 'card',
        name: 'Credit/Debit Card',
        description: 'All major cards accepted',
        icon: 'card-icon',
        enabled: true,
      },
      {
        id: 'netbanking',
        name: 'Net Banking',
        description: 'All major banks supported',
        icon: 'bank-icon',
        enabled: true,
      },
      {
        id: 'wallet',
        name: 'Wallet',
        description: 'Paytm, PhonePe, etc.',
        icon: 'wallet-icon',
        enabled: true,
      },
    ];
  }

  private static async handlePostPaymentActions(payment: any) {
    const metadata = payment.metadata as any;

    switch (metadata.type) {
      case 'consultation':
        await this.activateConsultation(metadata.referenceId);
        break;
      case 'program':
        await this.activateProgramEnrollment(payment.userId, metadata.referenceId);
        break;
      case 'subscription':
        await this.activateSubscription(payment.userId, metadata.referenceId);
        break;
    }

    // Send payment confirmation
    await this.sendPaymentConfirmation(payment);
  }

  private static async handlePaymentCaptured(data: any) {
    await prisma.payment.update({
      where: { gatewayPaymentId: data.id },
      data: {
        status: 'SUCCESS',
        paymentMethod: data.method,
      },
    });
  }

  private static async handlePaymentFailed(data: any) {
    await prisma.payment.update({
      where: { gatewayPaymentId: data.id },
      data: {
        status: 'FAILED',
        failureReason: data.error?.description,
      },
    });
  }

  private static async handleRefundProcessed(data: any) {
    await prisma.payment.update({
      where: { refundId: data.id },
      data: {
        status: data.amount === data.payment_amount ? 'REFUNDED' : 'PARTIALLY_REFUNDED',
      },
    });
  }

  private static async activateConsultation(consultationId: string) {
    // Implementation for activating consultation after payment
  }

  private static async activateProgramEnrollment(userId: string, programId: string) {
    // Implementation for activating program enrollment
  }

  private static async activateSubscription(userId: string, planId: string) {
    // Implementation for activating subscription
  }

  private static async sendPaymentConfirmation(payment: any) {
    // Send email confirmation
  }
}
```

#### 3. Razorpay Gateway Implementation
```typescript
// services/payment/src/services/gateways/razorpay.gateway.ts
import Razorpay from 'razorpay';
import crypto from 'crypto';
import { PaymentGateway } from './payment.gateway';

export class RazorpayGateway implements PaymentGateway {
  private razorpay: Razorpay;

  constructor() {
    this.razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID!,
      key_secret: process.env.RAZORPAY_KEY_SECRET!,
    });
  }

  async createOrder(data: {
    amount: number;
    currency: string;
    receipt: string;
    notes?: any;
  }) {
    const order = await this.razorpay.orders.create({
      amount: Math.round(data.amount * 100), // Convert to paise
      currency: data.currency,
      receipt: data.receipt,
      notes: data.notes,
    });

    return {
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      status: order.status,
    };
  }

  async verifySignature(data: {
    orderId: string;
    paymentId: string;
    signature: string;
  }): Promise<boolean> {
    const text = `${data.orderId}|${data.paymentId}`;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET!)
      .update(text)
      .digest('hex');

    return expectedSignature === data.signature;
  }

  async verifyWebhookSignature(payload: any, signature: string): Promise<boolean> {
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET!)
      .update(JSON.stringify(payload))
      .digest('hex');

    return expectedSignature === signature;
  }

  parseWebhookEvent(payload: any) {
    return {
      type: payload.event,
      data: payload.payload.payment?.entity || payload.payload.refund?.entity,
    };
  }

  async initiateRefund(data: {
    paymentId: string;
    amount: number;
    notes?: any;
  }) {
    const refund = await this.razorpay.payments.refund(data.paymentId, {
      amount: Math.round(data.amount * 100),
      notes: data.notes,
    });

    return {
      id: refund.id,
      amount: refund.amount,
      status: refund.status,
    };
  }

  async fetchPayment(paymentId: string) {
    return this.razorpay.payments.fetch(paymentId);
  }
}
```

### Day 4-5: Invoice Generation

#### 1. Invoice Service
```typescript
// services/payment/src/services/invoice.service.ts
import PDFDocument from 'pdfkit';
import { prisma } from '@nutrition/database';
import { uploadToStorage } from '../utils/storage';
import { formatCurrency, formatDate } from '../utils/format.utils';

export class InvoiceService {
  static async generateInvoice(paymentId: string) {
    const payment = await prisma.payment.findUnique({
      where: { id: paymentId },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    // Generate PDF
    const pdfBuffer = await this.createInvoicePDF(payment);

    // Upload to storage
    const filename = `invoices/${payment.invoiceNumber}.pdf`;
    const invoiceUrl = await uploadToStorage(pdfBuffer, filename, 'application/pdf');

    // Update payment with invoice URL
    await prisma.payment.update({
      where: { id: paymentId },
      data: { invoiceUrl },
    });

    return invoiceUrl;
  }

  static async getInvoice(paymentId: string, userId: string) {
    const payment = await prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId,
        status: 'SUCCESS',
      },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Invoice not found');
    }

    return {
      invoiceNumber: payment.invoiceNumber,
      invoiceUrl: payment.invoiceUrl,
      payment,
    };
  }

  static async generateInvoicePDF(paymentId: string, userId: string): Promise<Buffer> {
    const payment = await prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId,
        status: 'SUCCESS',
      },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    return this.createInvoicePDF(payment);
  }

  private static async createInvoicePDF(payment: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 50 });
      const buffers: Buffer[] = [];

      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', reject);

      // Header
      doc
        .fontSize(24)
        .text('INVOICE', 50, 50)
        .fontSize(10)
        .text(`Invoice Number: ${payment.invoiceNumber}`, 50, 80)
        .text(`Date: ${formatDate(payment.createdAt)}`, 50, 95);

      // Company Details
      doc
        .fontSize(16)
        .text('Nutrition Platform', 300, 50)
        .fontSize(10)
        .text('123 Health Street', 300, 75)
        .text('Mumbai, MH 400001', 300, 90)
        .text('GSTIN: 27AAAAA0000A1Z5', 300, 105);

      // Bill To
      doc
        .fontSize(12)
        .text('Bill To:', 50, 150)
        .fontSize(10)
        .text(
          `${payment.user.profile?.firstName} ${payment.user.profile?.lastName}`,
          50,
          170
        )
        .text(payment.user.email, 50, 185)
        .text(payment.user.phone || '', 50, 200);

      // Line Items
      doc.moveTo(50, 250).lineTo(550, 250).stroke();

      doc
        .fontSize(12)
        .text('Description', 50, 260)
        .text('Amount', 450, 260, { align: 'right' });

      doc.moveTo(50, 280).lineTo(550, 280).stroke();

      // Item details
      let description = '';
      if (payment.consultation) {
        description = `Consultation with ${payment.consultation.nutritionist.profile?.firstName} ${payment.consultation.nutritionist.profile?.lastName}`;
      } else if (payment.journey) {
        description = `${payment.journey.program.name} Program`;
      }

      doc
        .fontSize(10)
        .text(description, 50, 290)
        .text(formatCurrency(payment.amount, payment.currency), 450, 290, {
          align: 'right',
        });

      // GST Calculation
      const gstRate = 0.18; // 18% GST
      const baseAmount = payment.amount / (1 + gstRate);
      const gstAmount = payment.amount - baseAmount;

      doc
        .text('Subtotal', 350, 330)
        .text(formatCurrency(baseAmount, payment.currency), 450, 330, {
          align: 'right',
        })
        .text('GST (18%)', 350, 350)
        .text(formatCurrency(gstAmount, payment.currency), 450, 350, {
          align: 'right',
        });

      doc.moveTo(350, 370).lineTo(550, 370).stroke();

      doc
        .fontSize(12)
        .text('Total', 350, 380)
        .text(formatCurrency(payment.amount, payment.currency), 450, 380, {
          align: 'right',
        });

      // Payment Details
      doc
        .fontSize(10)
        .text('Payment Details:', 50, 450)
        .text(`Payment ID: ${payment.gatewayPaymentId}`, 50, 470)
        .text(`Payment Method: ${payment.paymentMethod || 'Online'}`, 50, 485)
        .text(`Status: ${payment.status}`, 50, 500);

      // Footer
      doc
        .fontSize(8)
        .text(
          'This is a computer-generated invoice and does not require a signature.',
          50,
          700,
          { align: 'center' }
        );

      doc.end();
    });
  }
}
```

### Day 6-7: Security Implementation

#### 1. Security Middleware
```typescript
// packages/security/src/middleware/security.middleware.ts
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://www.google-analytics.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.razorpay.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'self'", 'https://api.razorpay.com'],
    },
  },
  crossOriginEmbedderPolicy: false,
});

export const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true,
});

export const uploadRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Upload limit exceeded, please try again later.',
});

export const sanitizeInput = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized ${key} in request from ${req.ip}`);
  },
});

export const preventParamPollution = hpp({
  whitelist: ['sort', 'fields', 'page', 'limit'],
});

export const generateCSRFToken = (req: Request, res: Response, next: NextFunction) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
};

export const validateCSRFToken = (req: Request, res: Response, next: NextFunction) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const token = req.body._csrf || req.headers['x-csrf-token'];
  
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({
      success: false,
      error: 'Invalid CSRF token',
    });
  }

  next();
};

export const validateInput = (schema: any) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map((detail: any) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return res.status(400).json({
        success: false,
        errors,
      });
    }

    next();
  };
};

export const encryptSensitiveData = (data: any, fields: string[]) => {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  
  const encrypted = { ...data };

  fields.forEach((field) => {
    if (data[field]) {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      
      let encryptedData = cipher.update(data[field], 'utf8', 'hex');
      encryptedData += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      encrypted[field] = {
        data: encryptedData,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
      };
    }
  });

  return encrypted;
};

export const decryptSensitiveData = (data: any, fields: string[]) => {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  
  const decrypted = { ...data };

  fields.forEach((field) => {
    if (data[field] && typeof data[field] === 'object') {
      const { data: encryptedData, iv, authTag } = data[field];
      
      const decipher = crypto.createDecipheriv(
        algorithm,
        key,
        Buffer.from(iv, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
      decryptedData += decipher.final('utf8');
      
      decrypted[field] = decryptedData;
    }
  });

  return decrypted;
};
```

#### 2. API Security Service
```typescript
// packages/security/src/services/api-security.service.ts
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { prisma } from '@nutrition/database';

export class APISecurityService {
  private static readonly API_KEY_PREFIX = 'ntp_';
  private static readonly WEBHOOK_TOLERANCE = 300; // 5 minutes

  static async generateAPIKey(userId: string, name: string): Promise<string> {
    const key = `${this.API_KEY_PREFIX}${crypto.randomBytes(32).toString('hex')}`;
    const hashedKey = this.hashAPIKey(key);

    await prisma.apiKey.create({
      data: {
        userId,
        name,
        key: hashedKey,
        lastUsedAt: null,
      },
    });

    return key;
  }

  static async validateAPIKey(key: string): Promise<boolean> {
    if (!key.startsWith(this.API_KEY_PREFIX)) {
      return false;
    }

    const hashedKey = this.hashAPIKey(key);
    
    const apiKey = await prisma.apiKey.findUnique({
      where: { key: hashedKey },
      include: { user: true },
    });

    if (!apiKey || !apiKey.isActive) {
      return false;
    }

    // Update last used
    await prisma.apiKey.update({
      where: { id: apiKey.id },
      data: { lastUsedAt: new Date() },
    });

    return true;
  }

  static validateWebhookSignature(
    payload: string,
    signature: string,
    secret: string,
    timestamp?: number
  ): boolean {
    // Check timestamp to prevent replay attacks
    if (timestamp) {
      const currentTime = Math.floor(Date.now() / 1000);
      if (Math.abs(currentTime - timestamp) > this.WEBHOOK_TOLERANCE) {
        return false;
      }
    }

    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(timestamp ? `${timestamp}.${payload}` : payload)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  static generateRequestSignature(
    method: string,
    path: string,
    body: any,
    timestamp: number,
    secret: string
  ): string {
    const payload = `${method.toUpperCase()}${path}${JSON.stringify(body)}${timestamp}`;
    
    return crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');
  }

  static validateRequestSignature(req: Request, secret: string): boolean {
    const signature = req.headers['x-signature'] as string;
    const timestamp = parseInt(req.headers['x-timestamp'] as string);

    if (!signature || !timestamp) {
      return false;
    }

    const expectedSignature = this.generateRequestSignature(
      req.method,
      req.path,
      req.body,
      timestamp,
      secret
    );

    return this.validateWebhookSignature(
      JSON.stringify(req.body),
      signature,
      secret,
      timestamp
    );
  }

  static encryptAPIResponse(data: any, key: string): string {
    const algorithm = 'aes-256-cbc';
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);

    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return iv.toString('hex') + ':' + encrypted;
  }

  static decryptAPIRequest(encryptedData: string, key: string): any {
    const [ivHex, encrypted] = encryptedData.split(':');
    const algorithm = 'aes-256-cbc';
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  }

  private static hashAPIKey(key: string): string {
    return crypto
      .createHash('sha256')
      .update(key)
      .digest('hex');
  }

  static async logAPIAccess(req: Request, apiKeyId: string) {
    await prisma.apiAccessLog.create({
      data: {
        apiKeyId,
        method: req.method,
        path: req.path,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        statusCode: 200, // Will be updated by response interceptor
        responseTime: 0, // Will be updated by response interceptor
      },
    });
  }

  static generateJWT(payload: any, expiresIn: string = '1h'): string {
    return jwt.sign(payload, process.env.JWT_SECRET!, {
      expiresIn,
      algorithm: 'HS256',
    });
  }

  static verifyJWT(token: string): any {
    return jwt.verify(token, process.env.JWT_SECRET!);
  }
}
```

## Week 6: Quiz Engine & Recommendation System

### Day 1-3: Quiz Service Implementation

#### 1. Quiz Controller
```typescript
// services/quiz/src/controllers/quiz.controller.ts
import { Request, Response, NextFunction } from 'express';
import { QuizService } from '../services/quiz.service';
import { RecommendationService } from '../services/recommendation.service';
import { AppError } from '../utils/errors';

export class QuizController {
  static async getQuizByType(req: Request, res: Response, next: NextFunction) {
    try {
      const { type } = req.params;
      const userId = req.user?.userId;

      const quiz = await QuizService.getQuizByType(type);

      if (!quiz) {
        throw new AppError('Quiz not found', 404);
      }

      // Get previous results if user is authenticated
      let previousResult = null;
      if (userId) {
        previousResult = await QuizService.getLatestResult(userId, type);
      }

      res.json({
        success: true,
        data: {
          quiz,
          previousResult,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async submitQuiz(req: Request, res: Response, next: NextFunction) {
    try {
      const { type } = req.params;
      const { responses } = req.body;
      const userId = req.user?.userId;

      // Validate responses
      const validation = await QuizService.validateResponses(type, responses);
      if (!validation.valid) {
        throw new AppError('Invalid responses', 400, validation.errors);
      }

      // Process quiz
      const result = await QuizService.processQuizSubmission({
        quizType: type,
        responses,
        userId,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      // Generate recommendations
      const recommendations = await RecommendationService.generateRecommendations(
        result
      );

      res.json({
        success: true,
        data: {
          result,
          recommendations,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizResults(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { page = 1, limit = 10 } = req.query;

      const results = await QuizService.getUserQuizResults(userId, {
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: results,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizResult(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const result = await QuizService.getQuizResult(id, userId);

      if (!result) {
        throw new AppError('Quiz result not found', 404);
      }

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizAnalytics(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const analytics = await QuizService.getUserQuizAnalytics(userId);

      res.json({
        success: true,
        data: analytics,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Quiz Service
```typescript
// services/quiz/src/services/quiz.service.ts
import { prisma } from '@nutrition/database';
import { QuizEngine } from '../engines/quiz.engine';
import { SymptomQuizEngine } from '../engines/symptom.quiz.engine';
import { GutHealthQuizEngine } from '../engines/gut-health.quiz.engine';
import { StressQuizEngine } from '../engines/stress.quiz.engine';

interface QuizSubmission {
  quizType: string;
  responses: Record<string, any>;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export class QuizService {
  private static engines: Record<string, QuizEngine> = {
    symptom: new SymptomQuizEngine(),
    gut_health: new GutHealthQuizEngine(),
    stress: new StressQuizEngine(),
  };

  static async getQuizByType(type: string) {
    const quiz = await prisma.quiz.findFirst({
      where: {
        type: type.toUpperCase(),
        isActive: true,
      },
    });

    if (!quiz) {
      return null;
    }

    // Parse questions and add frontend-friendly structure
    const questions = quiz.questions as any[];
    const formattedQuestions = questions.map((q, index) => ({
      id: q.id || `q${index + 1}`,
      text: q.text,
      type: q.type || 'single_choice',
      required: q.required !== false,
      options: q.options || [],
      validation: q.validation || {},
      conditionalLogic: q.conditionalLogic || null,
    }));

    return {
      ...quiz,
      questions: formattedQuestions,
      estimatedTime: this.calculateEstimatedTime(formattedQuestions),
    };
  }

  static async validateResponses(
    quizType: string,
    responses: Record<string, any>
  ) {
    const quiz = await this.getQuizByType(quizType);
    if (!quiz) {
      return { valid: false, errors: ['Quiz not found'] };
    }

    const errors: string[] = [];
    const questions = quiz.questions as any[];

    for (const question of questions) {
      const response = responses[question.id];

      // Check required fields
      if (question.required && !response) {
        errors.push(`Question "${question.text}" is required`);
        continue;
      }

      // Validate response type
      if (response) {
        switch (question.type) {
          case 'single_choice':
            if (!question.options.find((opt: any) => opt.value === response)) {
              errors.push(`Invalid response for "${question.text}"`);
            }
            break;
          case 'multiple_choice':
            if (!Array.isArray(response)) {
              errors.push(`"${question.text}" requires multiple selections`);
            }
            break;
          case 'scale':
            const value = Number(response);
            if (isNaN(value) || value < 1 || value > 10) {
              errors.push(`"${question.text}" must be between 1 and 10`);
            }
            break;
          case 'text':
            if (question.validation?.maxLength && response.length > question.validation.maxLength) {
              errors.push(`"${question.text}" exceeds maximum length`);
            }
            break;
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async processQuizSubmission(submission: QuizSubmission) {
    const quiz = await prisma.quiz.findFirst({
      where: {
        type: submission.quizType.toUpperCase(),
        isActive: true,
      },
    });

    if (!quiz) {
      throw new Error('Quiz not found');
    }

    // Get the appropriate engine
    const engine = this.engines[submission.quizType.toLowerCase()];
    if (!engine) {
      throw new Error('Quiz engine not found');
    }

    // Calculate score and analysis
    const { score, analysis, riskFactors } = await engine.processResponses(
      submission.responses,
      quiz.scoring as any
    );

    // Save quiz result
    const result = await prisma.quizResult.create({
      data: {
        userId: submission.userId,
        quizId: quiz.id,
        quizType: quiz.type,
        responses: submission.responses,
        score,
        analysis,
        recommendations: await engine.generateRecommendations(score, analysis),
        ipAddress: submission.ipAddress,
        userAgent: submission.userAgent,
      },
    });

    // If user is authenticated, update their profile with insights
    if (submission.userId) {
      await this.updateUserInsights(submission.userId, quiz.type, analysis);
    }

    return result;
  }

  static async getLatestResult(userId: string, quizType: string) {
    return prisma.quizResult.findFirst({
      where: {
        userId,
        quizType: quizType.toUpperCase(),
      },
      orderBy: { completedAt: 'desc' },
    });
  }

  static async getUserQuizResults(userId: string, options: {
    page: number;
    limit: number;
  }) {
    const [results, total] = await Promise.all([
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          quiz: true,
        },
      }),
      prisma.quizResult.count({ where: { userId } }),
    ]);

    return {
      results,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getQuizResult(resultId: string, userId?: string) {
    const where: any = { id: resultId };
    
    // If userId is provided, ensure the result belongs to them
    if (userId) {
      where.userId = userId;
    }

    return prisma.quizResult.findFirst({
      where,
      include: {
        quiz: true,
      },
    });
  }

  static async getUserQuizAnalytics(userId: string) {
    const results = await prisma.quizResult.findMany({
      where: { userId },
      orderBy: { completedAt: 'asc' },
    });

    const analytics = {
      totalQuizzesTaken: results.length,
      quizzesByType: {} as Record<string, number>,
      progressOverTime: {} as Record<string, any[]>,
      latestInsights: {} as Record<string, any>,
    };

    // Group by quiz type
    results.forEach((result) => {
      const type = result.quizType;
      analytics.quizzesByType[type] = (analytics.quizzesByType[type] || 0) + 1;

      if (!analytics.progressOverTime[type]) {
        analytics.progressOverTime[type] = [];
      }

      analytics.progressOverTime[type].push({
        date: result.completedAt,
        score: result.score,
        insights: result.analysis,
      });

      // Keep latest insights
      if (!analytics.latestInsights[type] || 
          result.completedAt > analytics.latestInsights[type].date) {
        analytics.latestInsights[type] = {
          date: result.completedAt,
          analysis: result.analysis,
          recommendations: result.recommendations,
        };
      }
    });

    return analytics;
  }

  private static calculateEstimatedTime(questions: any[]): number {
    // Estimate based on question types
    let totalSeconds = 0;

    questions.forEach((question) => {
      switch (question.type) {
        case 'single_choice':
          totalSeconds += 10;
          break;
        case 'multiple_choice':
          totalSeconds += 15;
          break;
        case 'scale':
          totalSeconds += 8;
          break;
        case 'text':
          totalSeconds += 30;
          break;
        default:
          totalSeconds += 10;
      }
    });

    return Math.ceil(totalSeconds / 60); // Return in minutes
  }

  private static async updateUserInsights(
    userId: string,
    quizType: string,
    analysis: any
  ) {
    const profile = await prisma.userProfile.findUnique({
      where: { userId },
    });

    if (!profile) {
      return;
    }

    const currentInsights = profile.preferences?.healthInsights || {};
    currentInsights[quizType.toLowerCase()] = {
      ...analysis,
      updatedAt: new Date(),
    };

    await prisma.userProfile.update({
      where: { userId },
      data: {
        preferences: {
          ...profile.preferences,
          healthInsights: currentInsights,
        },
      },
    });
  }
}
```

#### 3. Quiz Engine Implementation
```typescript
// services/quiz/src/engines/symptom.quiz.engine.ts
import { QuizEngine } from './quiz.engine';

export class SymptomQuizEngine implements QuizEngine {
  async processResponses(responses: Record<string, any>, scoring: any) {
    let totalScore = 0;
    const categoryScores: Record<string, number> = {
      digestive: 0,
      energy: 0,
      mental: 0,
      hormonal: 0,
      immune: 0,
    };

    const riskFactors: string[] = [];

    // Process each response
    Object.entries(responses).forEach(([questionId, response]) => {
      const questionScoring = scoring[questionId];
      if (!questionScoring) return;

      // Calculate score based on response
      let questionScore = 0;
      if (typeof response === 'number') {
        questionScore = response;
      } else if (questionScoring.options?.[response]) {
        questionScore = questionScoring.options[response];
      }

      totalScore += questionScore;

      // Add to category scores
      if (questionScoring.category) {
        categoryScores[questionScoring.category] += questionScore;
      }

      // Check for risk factors
      if (questionScore >= 7) {
        riskFactors.push(questionScoring.riskMessage || questionId);
      }
    });

    // Analyze results
    const analysis = this.analyzeResults(totalScore, categoryScores, riskFactors);

    return {
      score: totalScore,
      analysis,
      riskFactors,
    };
  }

  private analyzeResults(
    totalScore: number,
    categoryScores: Record<string, number>,
    riskFactors: string[]
  ) {
    const maxPossibleScore = 100; // Adjust based on actual quiz
    const percentage = (totalScore / maxPossibleScore) * 100;

    let severity = 'low';
    let primaryConcern = '';
    let secondaryConcerns: string[] = [];

    // Determine severity
    if (percentage >= 70) {
      severity = 'high';
    } else if (percentage >= 40) {
      severity = 'moderate';
    }

    // Find primary concern
    const sortedCategories = Object.entries(categoryScores)
      .sort(([, a], [, b]) => b - a);

    if (sortedCategories.length > 0) {
      primaryConcern = sortedCategories[0][0];
      secondaryConcerns = sortedCategories
        .slice(1, 3)
        .filter(([, score]) => score > 0)
        .map(([category]) => category);
    }

    return {
      severity,
      percentage,
      primaryConcern,
      secondaryConcerns,
      categoryBreakdown: categoryScores,
      interpretation: this.getInterpretation(severity, primaryConcern),
    };
  }

  private getInterpretation(severity: string, primaryConcern: string): string {
    const interpretations: Record<string, Record<string, string>> = {
      low: {
        digestive: 'Your digestive health appears to be in good shape. Continue with your current healthy habits.',
        energy: 'Your energy levels seem stable. Maintain your current lifestyle practices.',
        mental: 'Your mental wellness indicators are positive. Keep up the good work!',
        hormonal: 'Your hormonal balance appears healthy. Continue monitoring for any changes.',
        immune: 'Your immune system seems to be functioning well. Keep supporting it with good nutrition.',
      },
      moderate: {
        digestive: 'You may be experiencing some digestive issues. Consider dietary adjustments and stress management.',
        energy: 'Your energy levels could use some support. Focus on sleep quality and balanced nutrition.',
        mental: 'Some stress or mood concerns noted. Consider mindfulness practices and adequate rest.',
        hormonal: 'Some hormonal imbalance indicators present. A targeted nutrition plan may help.',
        immune: 'Your immune system may need extra support. Focus on nutrient-dense foods and rest.',
      },
      high: {
        digestive: 'Significant digestive concerns identified. Professional guidance is recommended.',
        energy: 'Severe fatigue or energy issues detected. Consult with a healthcare provider.',
        mental: 'High stress or mood concerns present. Professional support may be beneficial.',
        hormonal: 'Significant hormonal imbalance indicators. Medical evaluation recommended.',
        immune: 'Your immune system appears compromised. Seek professional health guidance.',
      },
    };

    return interpretations[severity]?.[primaryConcern] || 
           'Based on your responses, a personalized consultation would be beneficial.';
  }

  async generateRecommendations(score: number, analysis: any) {
    const recommendations: any[] = [];

    // Program recommendations based on primary concern
    const programMap: Record<string, string> = {
      digestive: 'GUT_HEALTH',
      energy: 'METABOLIC_RESET',
      hormonal: 'PCOS_RESTORE',
      mental: 'STRESS_MANAGEMENT',
      immune: 'DETOX_HORMONE',
    };

    if (analysis.primaryConcern && programMap[analysis.primaryConcern]) {
      recommendations.push({
        type: 'program',
        priority: 'high',
        programType: programMap[analysis.primaryConcern],
        message: `Based on your ${analysis.primaryConcern} concerns, our ${programMap[analysis.primaryConcern].replace('_', ' ')} program may be ideal for you.`,
      });
    }

    // Lifestyle recommendations
    if (analysis.severity === 'moderate' || analysis.severity === 'high') {
      recommendations.push({
        type: 'consultation',
        priority: analysis.severity === 'high' ? 'urgent' : 'medium',
        message: 'A personalized consultation can help address your specific health concerns.',
      });
    }

    // Category-specific recommendations
    Object.entries(analysis.categoryBreakdown).forEach(([category, score]) => {
      if (score > 5) {
        recommendations.push(...this.getCategoryRecommendations(category, score));
      }
    });

    return recommendations;
  }

  private getCategoryRecommendations(category: string, score: number): any[] {
    const recommendations: Record<string, any[]> = {
      digestive: [
        {
          type: 'lifestyle',
          title: 'Improve Gut Health',
          suggestions: [
            'Include fermented foods daily',
            'Increase fiber intake gradually',
            'Stay hydrated with 8-10 glasses of water',
            'Consider a food sensitivity test',
          ],
        },
        {
          type: 'resource',
          title: '7-Day Gut Reset Guide',
          resourceId: 'gut-reset-guide',
        },
      ],
      energy: [
        {
          type: 'lifestyle',
          title: 'Boost Energy Naturally',
          suggestions: [
            'Prioritize 7-8 hours of quality sleep',
            'Balance blood sugar with protein at each meal',
            'Consider B-vitamin supplementation',
            'Reduce caffeine dependency',
          ],
        },
        {
          type: 'calculator',
          title: 'Calculate Your Ideal Macros',
          toolId: 'macro-calculator',
        },
      ],
      // ... other categories
    };

    return recommendations[category] || [];
  }
}
```

### Day 4-7: Recommendation Engine

#### 1. Recommendation Service
```typescript
// services/quiz/src/services/recommendation.service.ts
import { prisma } from '@nutrition/database';
import { MachineLearningService } from './ml.service';
import { ContentBasedFilter } from '../algorithms/content-based.filter';
import { CollaborativeFilter } from '../algorithms/collaborative.filter';

export class RecommendationService {
  static async generateRecommendations(quizResult: any) {
    const userId = quizResult.userId;
    const analysis = quizResult.analysis;

    // Get user history if authenticated
    let userHistory = null;
    if (userId) {
      userHistory = await this.getUserHistory(userId);
    }

    // Generate different types of recommendations
    const [
      programRecommendations,
      contentRecommendations,
      nutritionistRecommendations,
      resourceRecommendations,
    ] = await Promise.all([
      this.recommendPrograms(analysis, userHistory),
      this.recommendContent(analysis, userHistory),
      this.recommendNutritionists(analysis, userId),
      this.recommendResources(analysis),
    ]);

    // Combine and prioritize recommendations
    const combinedRecommendations = this.prioritizeRecommendations({
      programs: programRecommendations,
      content: contentRecommendations,
      nutritionists: nutritionistRecommendations,
      resources: resourceRecommendations,
    });

    // Track recommendations for analytics
    if (userId) {
      await this.trackRecommendations(userId, combinedRecommendations);
    }

    return combinedRecommendations;
  }

  private static async recommendPrograms(analysis: any, userHistory: any) {
    // Get all active programs
    const programs = await prisma.program.findMany({
      where: { isActive: true },
      include: {
        reviews: {
          select: { rating: true },
        },
      },
    });

    // Score programs based on analysis
    const scoredPrograms = programs.map((program) => {
      let score = 0;

      // Match program type with primary concern
      if (this.matchProgramToConcern(program.type, analysis.primaryConcern)) {
        score += 50;
      }

      // Consider secondary concerns
      analysis.secondaryConcerns.forEach((concern: string) => {
        if (this.matchProgramToConcern(program.type, concern)) {
          score += 20;
        }
      });

      // Factor in program ratings
      const avgRating = program.reviews.length > 0
        ? program.reviews.reduce((sum, r) => sum + r.rating, 0) / program.reviews.length
        : 3;
      score += avgRating * 10;

      // User history considerations
      if (userHistory) {
        // Avoid recommending completed programs
        if (userHistory.completedPrograms.includes(program.id)) {
          score -= 100;
        }
        // Boost programs similar to previously successful ones
        if (userHistory.successfulPrograms.includes(program.type)) {
          score += 30;
        }
      }

      return { ...program, score };
    });

    // Sort and return top programs
    return scoredPrograms
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(({ score, ...program }) => ({
        ...program,
        reason: this.generateProgramReason(program, analysis),
        confidence: Math.min(score / 100, 1),
      }));
  }

  private static async recommendContent(analysis: any, userHistory: any) {
    // Use content-based filtering
    const contentFilter = new ContentBasedFilter();
    
    // Get user interests from analysis
    const interests = this.extractInterestsFromAnalysis(analysis);

    // Get relevant blog posts
    const blogPosts = await prisma.blogPost.findMany({
      where: {
        isPublished: true,
        OR: interests.map((interest) => ({
          tags: { has: interest },
        })),
      },
      orderBy: { publishedAt: 'desc' },
      take: 20,
    });

    // Score and filter content
    const scoredContent = await contentFilter.scoreContent(
      blogPosts,
      interests,
      userHistory
    );

    return scoredContent.slice(0, 5);
  }

  private static async recommendNutritionists(analysis: any, userId?: string) {
    const nutritionists = await prisma.nutritionistProfile.findMany({
      where: { isActive: true },
      include: {
        user: {
          include: { profile: true },
        },
      },
    });

    // Score nutritionists based on specialization match
    const scored = nutritionists.map((nutritionist) => {
      let score = 0;

      // Match specializations with concerns
      const relevantSpecs = this.getRelevantSpecializations(analysis);
      relevantSpecs.forEach((spec) => {
        if (nutritionist.specializations.includes(spec)) {
          score += 30;
        }
      });

      // Consider ratings
      score += nutritionist.rating * 10;

      // Language preferences
      if (userId) {
        // Would check user's language preference
        score += 10;
      }

      return { ...nutritionist, score };
    });

    return scored
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(({ score, ...nutritionist }) => ({
        ...nutritionist,
        matchPercentage: Math.min((score / 100) * 100, 95),
      }));
  }

  private static async recommendResources(analysis: any) {
    const resourceTypes = this.getRelevantResourceTypes(analysis);

    const resources = await prisma.resource.findMany({
      where: {
        type: { in: resourceTypes },
        isPublic: true,
      },
      orderBy: { downloadCount: 'desc' },
      take: 10,
    });

    // Filter based on analysis
    return resources.filter((resource) => {
      const tags = resource.tags || [];
      return tags.some((tag) => 
        this.isTagRelevant(tag, analysis)
      );
    }).slice(0, 3);
  }

  private static prioritizeRecommendations(recommendations: any) {
    const prioritized: any[] = [];

    // High priority: Urgent health concerns
    if (recommendations.programs.some((p: any) => p.confidence > 0.8)) {
      prioritized.push({
        type: 'action',
        priority: 'high',
        title: 'Recommended Program',
        item: recommendations.programs[0],
        cta: 'Learn More',
      });
    }

    // Medium priority: Educational content
    recommendations.content.forEach((content: any, index: number) => {
      if (index < 2) {
        prioritized.push({
          type: 'content',
          priority: 'medium',
          title: content.title,
          item: content,
          cta: 'Read Article',
        });
      }
    });

    // Consultation recommendation if severity is high
    const shouldRecommendConsultation = true; // Based on analysis
    if (shouldRecommendConsultation) {
      prioritized.push({
        type: 'consultation',
        priority: 'high',
        title: 'Book a Free Discovery Call',
        item: {
          description: 'Get personalized guidance from our expert nutritionists',
          nutritionists: recommendations.nutritionists.slice(0, 2),
        },
        cta: 'Book Now',
      });
    }

    return prioritized;
  }

  private static async getUserHistory(userId: string) {
    const [journeys, quizResults, viewedContent] = await Promise.all([
      prisma.userJourney.findMany({
        where: { userId },
        include: { program: true },
      }),
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        take: 10,
      }),
      // Would fetch from analytics/audit logs
      [],
    ]);

    return {
      completedPrograms: journeys
        .filter((j) => j.status === 'COMPLETED')
        .map((j) => j.programId),
      successfulPrograms: journeys
        .filter((j) => j.status === 'COMPLETED' && j.progress?.satisfaction > 7)
        .map((j) => j.program.type),
      quizHistory: quizResults,
      viewedContent,
    };
  }

  private static matchProgramToConcern(programType: string, concern: string): boolean {
    const mapping: Record<string, string[]> = {
      GUT_HEALTH: ['digestive', 'bloating', 'ibs'],
      METABOLIC_RESET: ['energy', 'weight', 'metabolism'],
      PCOS_RESTORE: ['hormonal', 'pcos', 'fertility'],
      DIABETES_CARE: ['diabetes', 'blood_sugar', 'insulin'],
      DETOX_HORMONE: ['detox', 'hormonal', 'immune'],
    };

    return mapping[programType]?.includes(concern) || false;
  }

  private static generateProgramReason(program: any, analysis: any): string {
    const templates = [
      `Perfect for addressing your ${analysis.primaryConcern} concerns`,
      `${program._count?.journeys || 0} people with similar symptoms found success`,
      `Specifically designed for ${analysis.severity} ${analysis.primaryConcern} issues`,
    ];

    return templates[Math.floor(Math.random() * templates.length)];
  }

  private static extractInterestsFromAnalysis(analysis: any): string[] {
    const interests: string[] = [];

    // Map concerns to interests
    const concernToInterests: Record<string, string[]> = {
      digestive: ['gut-health', 'probiotics', 'digestion', 'ibs'],
      energy: ['metabolism', 'fatigue', 'nutrition', 'vitamins'],
      hormonal: ['hormones', 'pcos', 'thyroid', 'womens-health'],
      mental: ['stress', 'anxiety', 'mood', 'mindfulness'],
      immune: ['immunity', 'inflammation', 'detox', 'antioxidants'],
    };

    if (analysis.primaryConcern) {
      interests.push(...(concernToInterests[analysis.primaryConcern] || []));
    }

    analysis.secondaryConcerns.forEach((concern: string) => {
      interests.push(...(concernToInterests[concern] || []));
    });

    return [...new Set(interests)];
  }

  private static getRelevantSpecializations(analysis: any): string[] {
    const specs: string[] = [];

    if (analysis.primaryConcern === 'digestive') {
      specs.push('Gut Health', 'IBS Management');
    }
    if (analysis.primaryConcern === 'hormonal') {
      specs.push('Hormonal Balance', 'PCOS');
    }
    // ... more mappings

    return specs;
  }

  private static getRelevantResourceTypes(analysis: any): string[] {
    if (analysis.severity === 'high') {
      return ['tracker', 'guide', 'meal_plan'];
    }
    return ['guide', 'calculator', 'ebook'];
  }

  private static isTagRelevant(tag: string, analysis: any): boolean {
    const relevantTags = this.extractInterestsFromAnalysis(analysis);
    return relevantTags.some((interest) => 
      tag.toLowerCase().includes(interest.toLowerCase())
    );
  }

  private static async trackRecommendations(userId: string, recommendations: any[]) {
    // Store recommendations for analytics and ML training
    await prisma.recommendationLog.create({
      data: {
        userId,
        recommendations: recommendations,
        context: 'quiz_result',
        createdAt: new Date(),
      },
    });
  }
}
```

## Week 7: Content Management & PayloadCMS Integration

### Day 1-3: PayloadCMS Setup and Configuration

#### 1. PayloadCMS Configuration
```typescript
// apps/admin/src/payload.config.ts
import { buildConfig } from 'payload/config';
import path from 'path';
import { cloudStorage } from '@payloadcms/plugin-cloud-storage';
import { s3Adapter } from '@payloadcms/plugin-cloud-storage/s3';
import { seo } from '@payloadcms/plugin-seo';
import { formBuilder } from '@payloadcms/plugin-form-builder';

#### 1. Journey Controller
```typescript
// services/user/src/controllers/journey.controller.ts
import { Request, Response, NextFunction } from 'express';
import { JourneyService } from '../services/journey.service';
import { AppError } from '../utils/errors';

export class JourneyController {
  static async getCurrentJourney(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const journey = await JourneyService.getCurrentJourney(userId);

      res.json({
        success: true,
        data: journey,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getJourneyHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const journeys = await JourneyService.getJourneyHistory(userId);

      res.json({
        success: true,
        data: journeys,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createCheckIn(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const checkInData = req.body;

      const checkIn = await JourneyService.createCheckIn(userId, checkInData);

      res.json({
        success: true,
        message: 'Check-in recorded successfully',
        data: checkIn,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getCheckIns(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { journeyId } = req.params;
      const { startDate, endDate } = req.query;

      const checkIns = await JourneyService.getCheckIns(journeyId, userId, {
        startDate: startDate as string,
        endDate: endDate as string,
      });

      res.json({
        success: true,
        data: checkIns,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createMealEntry(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const mealData = req.body;

      const meal = await JourneyService.createMealEntry(userId, mealData);

      res.json({
        success: true,
        message: 'Meal entry recorded successfully',
        data: meal,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getMealEntries(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { date } = req.query;

      const meals = await JourneyService.getMealEntries(
        userId,
        date ? new Date(date as string) : new Date()
      );

      res.json({
        success: true,
        data: meals,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgressReport(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { journeyId } = req.params;

      const report = await JourneyService.generateProgressReport(journeyId, userId);

      res.json({
        success: true,
        data: report,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateMeasurements(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const measurements = req.body;

      const updated = await JourneyService.updateMeasurements(userId, measurements);

      res.json({
        success: true,
        message: 'Measurements updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Journey Service
```typescript
// services/user/src/services/journey.service.ts
import { prisma } from '@nutrition/database';
import { calculateCalories, analyzeMacros } from '../utils/nutrition.calculations';
import { generateChartData } from '../utils/chart.utils';

export class JourneyService {
  static async getCurrentJourney(userId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
      include: {
        program: true,
        checkIns: {
          orderBy: { date: 'desc' },
          take: 7,
        },
        mealEntries: {
          where: {
            date: {
              gte: new Date(new Date().setHours(0, 0, 0, 0)),
            },
          },
        },
      },
    });

    if (!journey) {
      return null;
    }

    // Calculate progress
    const totalDays = journey.program.duration;
    const elapsedDays = Math.floor(
      (new Date().getTime() - journey.startDate.getTime()) / (1000 * 60 * 60 * 24)
    );
    const progressPercentage = Math.min((elapsedDays / totalDays) * 100, 100);

    // Calculate today's nutrition
    const todayNutrition = this.calculateDailyNutrition(journey.mealEntries);

    return {
      ...journey,
      progress: {
        percentage: progressPercentage,
        elapsedDays,
        remainingDays: Math.max(totalDays - elapsedDays, 0),
      },
      todayNutrition,
    };
  }

  static async getJourneyHistory(userId: string) {
    return prisma.userJourney.findMany({
      where: { userId },
      include: {
        program: true,
        payments: {
          where: { status: 'SUCCESS' },
        },
      },
      orderBy: { startDate: 'desc' },
    });
  }

  static async createCheckIn(userId: string, data: any) {
    // Get active journey
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    // Create check-in
    const checkIn = await prisma.journeyCheckIn.create({
      data: {
        journeyId: journey.id,
        date: new Date(),
        ...data,
      },
    });

    // Update journey measurements if weight is provided
    if (data.weight) {
      await this.updateJourneyMeasurements(journey.id, { weight: data.weight });
    }

    return checkIn;
  }

  static async getCheckIns(journeyId: string, userId: string, filters: any) {
    // Verify journey belongs to user
    const journey = await prisma.userJourney.findFirst({
      where: {
        id: journeyId,
        userId,
      },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    const where: any = { journeyId };

    if (filters.startDate) {
      where.date = { gte: new Date(filters.startDate) };
    }

    if (filters.endDate) {
      where.date = { ...where.date, lte: new Date(filters.endDate) };
    }

    return prisma.journeyCheckIn.findMany({
      where,
      orderBy: { date: 'desc' },
    });
  }

  static async createMealEntry(userId: string, data: any) {
    // Get active journey
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    // Calculate nutrition info
    const nutritionInfo = await calculateCalories(data.foods);

    return prisma.mealEntry.create({
      data: {
        journeyId: journey.id,
        date: new Date(),
        mealType: data.mealType,
        foods: data.foods,
        ...nutritionInfo,
        notes: data.notes,
        photo: data.photo,
      },
    });
  }

  static async getMealEntries(userId: string, date: Date) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      return [];
    }

    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);

    return prisma.mealEntry.findMany({
      where: {
        journeyId: journey.id,
        date: {
          gte: startOfDay,
          lte: endOfDay,
        },
      },
      orderBy: { date: 'asc' },
    });
  }

  static async generateProgressReport(journeyId: string, userId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        id: journeyId,
        userId,
      },
      include: {
        program: true,
        checkIns: {
          orderBy: { date: 'asc' },
        },
        mealEntries: {
          orderBy: { date: 'asc' },
        },
      },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    // Generate various analytics
    const weightProgress = generateChartData(
      journey.checkIns.filter(c => c.weight),
      'date',
      'weight'
    );

    const energyTrend = generateChartData(
      journey.checkIns.filter(c => c.energy),
      'date',
      'energy'
    );

    const nutritionSummary = analyzeMacros(journey.mealEntries);

    // Calculate achievements
    const achievements = this.calculateAchievements(journey);

    return {
      journey: {
        id: journey.id,
        program: journey.program.name,
        startDate: journey.startDate,
        progress: journey.progress,
      },
      charts: {
        weightProgress,
        energyTrend,
      },
      nutritionSummary,
      achievements,
      recommendations: this.generateRecommendations(journey),
    };
  }

  static async updateMeasurements(userId: string, measurements: any) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    return this.updateJourneyMeasurements(journey.id, measurements);
  }

  private static async updateJourneyMeasurements(journeyId: string, measurements: any) {
    const journey = await prisma.userJourney.findUnique({
      where: { id: journeyId },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    const currentMeasurements = journey.measurements || {};
    const updatedMeasurements = {
      ...currentMeasurements,
      ...measurements,
      lastUpdated: new Date(),
    };

    return prisma.userJourney.update({
      where: { id: journeyId },
      data: { measurements: updatedMeasurements },
    });
  }

  private static calculateDailyNutrition(mealEntries: any[]) {
    return mealEntries.reduce(
      (total, meal) => ({
        calories: total.calories + (meal.calories || 0),
        protein: total.protein + (meal.protein || 0),
        carbs: total.carbs + (meal.carbs || 0),
        fat: total.fat + (meal.fat || 0),
        fiber: total.fiber + (meal.fiber || 0),
      }),
      { calories: 0, protein: 0, carbs: 0, fat: 0, fiber: 0 }
    );
  }

  private static calculateAchievements(journey: any) {
    const achievements = [];

    // Check-in streak
    const checkInDates = journey.checkIns.map((c: any) => 
      new Date(c.date).toDateString()
    );
    const uniqueDates = [...new Set(checkInDates)];
    
    if (uniqueDates.length >= 7) {
      achievements.push({
        type: 'streak',
        title: 'Week Warrior',
        description: 'Checked in for 7 days',
      });
    }

    // Weight loss
    if (journey.checkIns.length > 1) {
      const firstWeight = journey.checkIns[0].weight;
      const lastWeight = journey.checkIns[journey.checkIns.length - 1].weight;
      
      if (firstWeight && lastWeight && lastWeight < firstWeight) {
        const loss = firstWeight - lastWeight;
        achievements.push({
          type: 'weight_loss',
          title: 'Progress Made',
          description: `Lost ${loss.toFixed(1)} kg`,
        });
      }
    }

    return achievements;
  }

  private static generateRecommendations(journey: any) {
    const recommendations = [];

    // Analyze recent check-ins
    const recentCheckIns = journey.checkIns.slice(-7);
    const avgEnergy = recentCheckIns.reduce((sum: number, c: any) => 
      sum + (c.energy || 0), 0
    ) / recentCheckIns.length;

    if (avgEnergy < 5) {
      recommendations.push({
        type: 'energy',
        priority: 'high',
        message: 'Your energy levels seem low. Consider reviewing your sleep schedule and stress management.',
      });
    }

    // Analyze nutrition
    const recentMeals = journey.mealEntries.slice(-21); // Last week
    const avgProtein = recentMeals.reduce((sum: number, m: any) => 
      sum + (m.protein || 0), 0
    ) / recentMeals.length;

    if (avgProtein < 20) {
      recommendations.push({
        type: 'nutrition',
        priority: 'medium',
        message: 'Your protein intake appears low. Try to include more protein-rich foods in your meals.',
      });
    }

    return recommendations;
  }
}
```

## Week 4: Program & Consultation Management

### Day 1-2: Program Service

#### 1. Program Controller
```typescript
// services/consultation/src/controllers/program.controller.ts
import { Request, Response, NextFunction } from 'express';
import { ProgramService } from '../services/program.service';
import { AppError } from '../utils/errors';

export class ProgramController {
  static async getAllPrograms(req: Request, res: Response, next: NextFunction) {
    try {
      const { type, featured, page = 1, limit = 10 } = req.query;

      const programs = await ProgramService.getAllPrograms({
        type: type as string,
        featured: featured === 'true',
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: programs,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramBySlug(req: Request, res: Response, next: NextFunction) {
    try {
      const { slug } = req.params;
      const userId = req.user?.userId;

      const program = await ProgramService.getProgramBySlug(slug, userId);

      if (!program) {
        throw new AppError('Program not found', 404);
      }

      res.json({
        success: true,
        data: program,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramDetails(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const details = await ProgramService.getProgramDetails(id, userId);

      res.json({
        success: true,
        data: details,
      });
    } catch (error) {
      next(error);
    }
  }

  static async enrollInProgram(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { startDate } = req.body;

      const enrollment = await ProgramService.enrollInProgram(userId, id, startDate);

      res.json({
        success: true,
        message: 'Successfully enrolled in program',
        data: enrollment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getRecommendedPrograms(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.user?.userId;

      const recommendations = await ProgramService.getRecommendedPrograms(userId);

      res.json({
        success: true,
        data: recommendations,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createReview(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { rating, title, comment } = req.body;

      const review = await ProgramService.createReview(userId, id, {
        rating,
        title,
        comment,
      });

      res.json({
        success: true,
        message: 'Review submitted successfully',
        data: review,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramReviews(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { page = 1, limit = 10 } = req.query;

      const reviews = await ProgramService.getProgramReviews(id, {
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: reviews,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Program Service
```typescript
// services/consultation/src/services/program.service.ts
import { prisma } from '@nutrition/database';
import { cacheManager } from '../utils/cache';
import { calculateProgramScore } from '../utils/recommendation.engine';

export class ProgramService {
  private static readonly CACHE_PREFIX = 'program:';
  private static readonly CACHE_TTL = 3600; // 1 hour

  static async getAllPrograms(options: {
    type?: string;
    featured?: boolean;
    page: number;
    limit: number;
  }) {
    const where: any = {
      isActive: true,
    };

    if (options.type) {
      where.type = options.type;
    }

    if (options.featured !== undefined) {
      where.isFeatured = options.featured;
    }

    const [programs, total] = await Promise.all([
      prisma.program.findMany({
        where,
        orderBy: [
          { isFeatured: 'desc' },
          { order: 'asc' },
          { createdAt: 'desc' },
        ],
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          _count: {
            select: {
              reviews: true,
              journeys: true,
            },
          },
        },
      }),
      prisma.program.count({ where }),
    ]);

    // Calculate average ratings
    const programsWithRatings = await Promise.all(
      programs.map(async (program) => {
        const avgRating = await prisma.programReview.aggregate({
          where: { programId: program.id },
          _avg: { rating: true },
        });

        return {
          ...program,
          averageRating: avgRating._avg.rating || 0,
        };
      })
    );

    return {
      programs: programsWithRatings,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getProgramBySlug(slug: string, userId?: string) {
    // Try cache first
    const cacheKey = `${this.CACHE_PREFIX}slug:${slug}`;
    const cached = await cacheManager.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const program = await prisma.program.findUnique({
      where: { slug, isActive: true },
      include: {
        reviews: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          include: {
            user: {
              select: {
                profile: {
                  select: {
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            },
          },
        },
        _count: {
          select: {
            reviews: true,
            journeys: true,
          },
        },
      },
    });

    if (!program) {
      return null;
    }

    // Calculate stats
    const [avgRating, completionRate] = await Promise.all([
      prisma.programReview.aggregate({
        where: { programId: program.id },
        _avg: { rating: true },
      }),
      this.calculateCompletionRate(program.id),
    ]);

    const enrichedProgram = {
      ...program,
      stats: {
        averageRating: avgRating._avg.rating || 0,
        totalReviews: program._count.reviews,
        totalEnrollments: program._count.journeys,
        completionRate,
      },
    };

    // Cache the result
    await cacheManager.set(cacheKey, JSON.stringify(enrichedProgram), this.CACHE_TTL);

    // Track view if user is logged in
    if (userId) {
      await this.trackProgramView(userId, program.id);
    }

    return enrichedProgram;
  }

  static async getProgramDetails(programId: string, userId?: string) {
    const program = await prisma.program.findUnique({
      where: { id: programId, isActive: true },
    });

    if (!program) {
      throw new Error('Program not found');
    }

    // Get detailed information
    const [
      weeklySchedule,
      sampleMealPlan,
      successStories,
      faqs,
      userProgress,
    ] = await Promise.all([
      this.getWeeklySchedule(programId),
      this.getSampleMealPlan(program.type),
      this.getSuccessStories(programId),
      this.getProgramFAQs(program.type),
      userId ? this.getUserProgramProgress(userId, programId) : null,
    ]);

    return {
      program,
      details: {
        weeklySchedule,
        sampleMealPlan,
        successStories,
        faqs,
      },
      userProgress,
    };
  }

  static async enrollInProgram(userId: string, programId: string, startDate?: Date) {
    // Check if already enrolled
    const existingJourney = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
        status: { in: ['ACTIVE', 'PAUSED'] },
      },
    });

    if (existingJourney) {
      throw new Error('Already enrolled in this program');
    }

    // Get program details
    const program = await prisma.program.findUnique({
      where: { id: programId },
    });

    if (!program) {
      throw new Error('Program not found');
    }

    // Create journey
    const journey = await prisma.userJourney.create({
      data: {
        userId,
        programId,
        startDate: startDate || new Date(),
        endDate: null, // Will be calculated based on progress
        status: 'ACTIVE',
        progress: {
          currentWeek: 1,
          completedModules: [],
          milestones: [],
        },
      },
    });

    // Create initial meal plan
    await this.createInitialMealPlan(journey.id, program.type);

    // Schedule welcome email
    await this.scheduleWelcomeSequence(userId, programId);

    return journey;
  }

  static async getRecommendedPrograms(userId?: string) {
    if (!userId) {
      // Return popular programs for non-authenticated users
      return this.getPopularPrograms();
    }

    // Get user data for recommendation
    const [userData, quizResults, previousPrograms] = await Promise.all([
      prisma.user.findUnique({
        where: { id: userId },
        include: {
          profile: true,
          journeys: {
            include: { program: true },
          },
        },
      }),
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        take: 5,
      }),
      prisma.userJourney.findMany({
        where: { userId },
        include: { program: true },
      }),
    ]);

    if (!userData) {
      return this.getPopularPrograms();
    }

    // Get all active programs
    const programs = await prisma.program.findMany({
      where: { isActive: true },
      include: {
        _count: {
          select: {
            reviews: true,
            journeys: true,
          },
        },
      },
    });

    // Score each program based on user data
    const scoredPrograms = programs.map((program) => ({
      ...program,
      score: calculateProgramScore(program, {
        userData,
        quizResults,
        previousPrograms,
      }),
    }));

    // Sort by score and return top 5
    return scoredPrograms
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map(({ score, ...program }) => program);
  }

  static async createReview(userId: string, programId: string, data: {
    rating: number;
    title?: string;
    comment?: string;
  }) {
    // Check if user has completed the program
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
        status: 'COMPLETED',
      },
    });

    if (!journey) {
      throw new Error('You must complete the program before reviewing');
    }

    // Check if already reviewed
    const existingReview = await prisma.programReview.findUnique({
      where: {
        programId_userId: {
          programId,
          userId,
        },
      },
    });

    if (existingReview) {
      throw new Error('You have already reviewed this program');
    }

    // Create review
    const review = await prisma.programReview.create({
      data: {
        programId,
        userId,
        rating: data.rating,
        title: data.title,
        comment: data.comment,
        isVerified: true, // Since they completed the program
      },
    });

    // Update program rating cache
    await this.updateProgramRatingCache(programId);

    return review;
  }

  static async getProgramReviews(programId: string, options: {
    page: number;
    limit: number;
  }) {
    const [reviews, total] = await Promise.all([
      prisma.programReview.findMany({
        where: { programId },
        orderBy: [
          { isVerified: 'desc' },
          { createdAt: 'desc' },
        ],
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          user: {
            select: {
              profile: {
                select: {
                  firstName: true,
                  lastName: true,
                  avatar: true,
                },
              },
            },
          },
        },
      }),
      prisma.programReview.count({ where: { programId } }),
    ]);

    // Get rating distribution
    const ratingDistribution = await prisma.programReview.groupBy({
      by: ['rating'],
      where: { programId },
      _count: true,
    });

    return {
      reviews,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
      stats: {
        distribution: ratingDistribution.reduce((acc, item) => {
          acc[item.rating] = item._count;
          return acc;
        }, {} as Record<number, number>),
      },
    };
  }

  private static async calculateCompletionRate(programId: string) {
    const journeys = await prisma.userJourney.findMany({
      where: { programId },
      select: { status: true },
    });

    if (journeys.length === 0) return 0;

    const completed = journeys.filter(j => j.status === 'COMPLETED').length;
    return Math.round((completed / journeys.length) * 100);
  }

  private static async getPopularPrograms() {
    return prisma.program.findMany({
      where: { isActive: true, isFeatured: true },
      orderBy: { order: 'asc' },
      take: 5,
    });
  }

  private static async trackProgramView(userId: string, programId: string) {
    // Implement view tracking for analytics
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'VIEW_PROGRAM',
        entity: 'program',
        entityId: programId,
      },
    });
  }

  private static async getWeeklySchedule(programId: string) {
    // This would be stored in program metadata or a separate table
    // For now, returning a sample structure
    return {
      week1: {
        title: 'Foundation Week',
        activities: [
          'Initial health assessment',
          'Personalized meal plan creation',
          'Introduction to food journaling',
        ],
      },
      week2: {
        title: 'Implementation Week',
        activities: [
          'Start meal plan',
          'Daily check-ins',
          'First consultation call',
        ],
      },
      // ... more weeks
    };
  }

  private static async getSampleMealPlan(programType: string) {
    // Fetch from a meal plan service or database
    // This is a simplified example
    const mealPlans: Record<string, any> = {
      GUT_HEALTH: {
        day1: {
          breakfast: 'Overnight oats with chia seeds and berries',
          lunch: 'Grilled chicken salad with fermented vegetables',
          dinner: 'Baked salmon with steamed broccoli and quinoa',
          snacks: ['Apple slices with almond butter', 'Kefir smoothie'],
        },
        // ... more days
      },
      // ... other program types
    };

    return mealPlans[programType] || {};
  }

  private static async getSuccessStories(programId: string) {
    return prisma.programReview.findMany({
      where: {
        programId,
        rating: { gte: 4 },
        comment: { not: null },
        isVerified: true,
      },
      select: {
        rating: true,
        title: true,
        comment: true,
        createdAt: true,
        user: {
          select: {
            profile: {
              select: {
                firstName: true,
              },
            },
          },
        },
      },
      take: 3,
      orderBy: { rating: 'desc' },
    });
  }

  private static async getProgramFAQs(programType: string) {
    // This would be fetched from a CMS or database
    // Simplified example
    const faqs: Record<string, any[]> = {
      GUT_HEALTH: [
        {
          question: 'How long before I see results?',
          answer: 'Most clients report improvements in bloating and digestion within 2-3 weeks.',
        },
        {
          question: 'Can I follow this program if I have food allergies?',
          answer: 'Yes, all meal plans are customized based on your dietary restrictions.',
        },
      ],
      // ... other types
    };

    return faqs[programType] || [];
  }

  private static async getUserProgramProgress(userId: string, programId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!journey) {
      return null;
    }

    return {
      status: journey.status,
      startDate: journey.startDate,
      progress: journey.progress,
      completedAt: journey.completedAt,
    };
  }

  private static async createInitialMealPlan(journeyId: string, programType: string) {
    // This would integrate with a meal planning service
    // For now, we'll store a reference in the journey
    await prisma.userJourney.update({
      where: { id: journeyId },
      data: {
        mealPlans: {
          week1: 'Generated based on program type',
          status: 'pending_nutritionist_review',
        },
      },
    });
  }

  private static async scheduleWelcomeSequence(userId: string, programId: string) {
    // Schedule a series of welcome emails
    const emailSequence = [
      { delay: 0, template: 'program_welcome' },
      { delay: 1, template: 'program_day1_tips' },
      { delay: 3, template: 'program_check_in' },
      { delay: 7, template: 'program_week1_summary' },
    ];

    for (const email of emailSequence) {
      await prisma.notification.create({
        data: {
          userId,
          type: 'email',
          category: 'journey',
          title: `Program Email - ${email.template}`,
          content: JSON.stringify({ programId, template: email.template }),
          status: 'PENDING',
          createdAt: new Date(Date.now() + email.delay * 24 * 60 * 60 * 1000),
        },
      });
    }
  }

  private static async updateProgramRatingCache(programId: string) {
    const avgRating = await prisma.programReview.aggregate({
      where: { programId },
      _avg: { rating: true },
      _count: true,
    });

    // Update cache
    const cacheKey = `${this.CACHE_PREFIX}rating:${programId}`;
    await cacheManager.set(
      cacheKey,
      JSON.stringify({
        average: avgRating._avg.rating || 0,
        count: avgRating._count,
      }),
      86400 // 24 hours
    );
  }
}: '<rootDir>/src/$1',
    '^@nutrition/(.*)# Comprehensive Weekly Implementation Guide - Functional Nutrition Platform

## Week 1: Project Foundation & Infrastructure Setup

### Day 1-2: Repository and Monorepo Setup

#### 1. Initialize Monorepo Structure
```bash
# Create project directory
mkdir nutrition-platform && cd nutrition-platform

# Initialize git repository
git init

# Create monorepo structure
mkdir -p apps/{web,api,admin,mobile-pwa}
mkdir -p packages/{ui,utils,types,config,database}
mkdir -p services/{auth,user,consultation,payment,content,quiz,notification,analytics}
mkdir -p infrastructure/{docker,kubernetes,terraform,scripts}
mkdir -p docs/{api,architecture,deployment}

# Initialize npm workspaces
npm init -y
```

#### 2. Setup package.json for Workspaces
```json
{
  "name": "nutrition-platform",
  "private": true,
  "workspaces": [
    "apps/*",
    "packages/*",
    "services/*"
  ],
  "scripts": {
    "dev": "turbo run dev",
    "build": "turbo run build",
    "test": "turbo run test",
    "lint": "turbo run lint",
    "format": "prettier --write \"**/*.{ts,tsx,js,jsx,json,md}\"",
    "prepare": "husky install"
  },
  "devDependencies": {
    "turbo": "^1.11.0",
    "@types/node": "^20.10.0",
    "typescript": "^5.3.0",
    "prettier": "^3.1.0",
    "eslint": "^8.55.0",
    "husky": "^8.0.3",
    "lint-staged": "^15.2.0"
  }
}
```

#### 3. Setup Turborepo Configuration
```json
// turbo.json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": [".next/**", "dist/**"]
    },
    "dev": {
      "cache": false,
      "persistent": true
    },
    "test": {
      "dependsOn": ["build"],
      "inputs": ["src/**", "tests/**"]
    },
    "lint": {},
    "type-check": {}
  }
}
```

#### 4. Setup TypeScript Configuration
```json
// tsconfig.base.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "jsx": "preserve",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "moduleResolution": "node",
    "baseUrl": ".",
    "paths": {
      "@nutrition/*": ["packages/*/src"]
    }
  },
  "exclude": ["node_modules", "dist", ".next", "coverage"]
}
```

### Day 3-4: Docker Environment Setup

#### 1. Create Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: nutrition_postgres
    environment:
      POSTGRES_USER: nutrition_user
      POSTGRES_PASSWORD: nutrition_password
      POSTGRES_DB: nutrition_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./infrastructure/docker/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nutrition_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: nutrition_redis
    command: redis-server --requirepass nutrition_redis_password
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    container_name: nutrition_minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: nutrition_minio_user
      MINIO_ROOT_PASSWORD: nutrition_minio_password
    volumes:
      - minio_data:/data
    ports:
      - "9000:9000"
      - "9001:9001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 20s
      retries: 3

  meilisearch:
    image: getmeili/meilisearch:latest
    container_name: nutrition_meilisearch
    environment:
      MEILI_MASTER_KEY: nutrition_meilisearch_key
      MEILI_ENV: development
    volumes:
      - meilisearch_data:/meili_data
    ports:
      - "7700:7700"

  mailhog:
    image: mailhog/mailhog:latest
    container_name: nutrition_mailhog
    ports:
      - "1025:1025"
      - "8025:8025"

volumes:
  postgres_data:
  redis_data:
  minio_data:
  meilisearch_data:
```

#### 2. Create Development Dockerfile
```dockerfile
# Dockerfile.dev
FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat
RUN apk update
WORKDIR /app

# Install dependencies
FROM base AS deps
COPY package.json package-lock.json ./
COPY apps/*/package.json apps/*/
COPY packages/*/package.json packages/*/
COPY services/*/package.json services/*/
RUN npm ci

# Development
FROM base AS dev
COPY --from=deps /app/node_modules ./node_modules
COPY . .
EXPOSE 3000 4000
CMD ["npm", "run", "dev"]
```

### Day 5: CI/CD Pipeline Setup

#### 1. GitHub Actions Configuration
```yaml
# .github/workflows/main.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  NODE_VERSION: '20'
  PNPM_VERSION: '8'

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Run ESLint
        run: npm run lint
      - name: Run Type Check
        run: npm run type-check

  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test_password
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Run unit tests
        run: npm run test:unit
      - name: Run integration tests
        run: npm run test:integration
        env:
          DATABASE_URL: postgresql://postgres:test_password@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379

  build:
    needs: [lint, test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Build applications
        run: npm run build
      - name: Build Docker images
        run: |
          docker build -f Dockerfile.api -t nutrition-api:${{ github.sha }} .
          docker build -f Dockerfile.web -t nutrition-web:${{ github.sha }} .
      - name: Push to registry
        if: github.ref == 'refs/heads/main'
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push nutrition-api:${{ github.sha }}
          docker push nutrition-web:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Deploy to staging
        run: |
          # Deploy to Kubernetes or other platform
          echo "Deploying to staging..."
```

#### 2. Environment Configuration
```bash
# .env.example
# Application
NODE_ENV=development
PORT=4000
CLIENT_URL=http://localhost:3000
API_URL=http://localhost:4000

# Database
DATABASE_URL=postgresql://nutrition_user:nutrition_password@localhost:5432/nutrition_db
REDIS_URL=redis://:nutrition_redis_password@localhost:6379

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# 2FA
TWO_FA_APP_NAME=NutritionPlatform

# File Storage
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_ACCESS_KEY=nutrition_minio_user
MINIO_SECRET_KEY=nutrition_minio_password
MINIO_BUCKET=nutrition-uploads

# Search
MEILISEARCH_HOST=http://localhost:7700
MEILISEARCH_KEY=nutrition_meilisearch_key

# Email (Development)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=
SMTP_PASS=
EMAIL_FROM=noreply@nutritionplatform.com

# Payment Gateway
RAZORPAY_KEY_ID=your_razorpay_key
RAZORPAY_KEY_SECRET=your_razorpay_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# WhatsApp
WHATSAPP_API_URL=https://api.whatsapp.com/v1
WHATSAPP_TOKEN=your_whatsapp_token
WHATSAPP_PHONE_ID=your_phone_id

# SMS
SMS_PROVIDER=msg91
MSG91_AUTH_KEY=your_msg91_key
MSG91_SENDER_ID=NUTRIT

# Analytics
GA_TRACKING_ID=G-XXXXXXXXXX
HOTJAR_SITE_ID=1234567

# PayloadCMS
PAYLOAD_SECRET=your-payload-secret
PAYLOAD_CONFIG_PATH=src/payload.config.ts
```

### Day 6-7: Database Schema Implementation

#### 1. Prisma Setup and Schema
```bash
# Install Prisma
cd packages/database
npm init -y
npm install prisma @prisma/client
npm install -D @types/node typescript

# Initialize Prisma
npx prisma init
```

```prisma
// packages/database/prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// Enums
enum UserRole {
  USER
  NUTRITIONIST
  ADMIN
}

enum Gender {
  MALE
  FEMALE
  OTHER
  PREFER_NOT_TO_SAY
}

enum ConsultationStatus {
  SCHEDULED
  IN_PROGRESS
  COMPLETED
  CANCELLED
  NO_SHOW
}

enum PaymentStatus {
  PENDING
  PROCESSING
  SUCCESS
  FAILED
  REFUNDED
}

enum ProgramType {
  GUT_HEALTH
  METABOLIC_RESET
  PCOS_RESTORE
  DIABETES_CARE
  DETOX_HORMONE
  CUSTOM
}

enum QuizType {
  SYMPTOM
  GUT_HEALTH
  STRESS
  NUTRITION
  LIFESTYLE
}

// Models
model User {
  id              String    @id @default(uuid())
  email           String    @unique
  phone           String?   @unique
  passwordHash    String    @map("password_hash")
  role            UserRole  @default(USER)
  emailVerified   Boolean   @default(false) @map("email_verified")
  phoneVerified   Boolean   @default(false) @map("phone_verified")
  twoFASecret     String?   @map("two_fa_secret")
  twoFAEnabled    Boolean   @default(false) @map("two_fa_enabled")
  lastLoginAt     DateTime? @map("last_login_at")
  createdAt       DateTime  @default(now()) @map("created_at")
  updatedAt       DateTime  @updatedAt @map("updated_at")

  // Relations
  profile              UserProfile?
  consultations        Consultation[]
  payments            Payment[]
  quizResults         QuizResult[]
  journeys            UserJourney[]
  documents           Document[]
  notifications       Notification[]
  refreshTokens       RefreshToken[]
  nutritionistProfile NutritionistProfile?
  consultationsAsNutritionist Consultation[] @relation("NutritionistConsultations")

  @@map("users")
  @@index([email])
  @@index([phone])
}

model UserProfile {
  id            String    @id @default(uuid())
  userId        String    @unique @map("user_id")
  firstName     String    @map("first_name")
  lastName      String    @map("last_name")
  dateOfBirth   DateTime? @map("date_of_birth")
  gender        Gender?
  avatar        String?
  bio           String?
  height        Float?    // in cm
  weight        Float?    // in kg
  bloodGroup    String?   @map("blood_group")
  allergies     String[]
  medications   String[]
  medicalHistory Json?    @map("medical_history")
  preferences   Json?
  timezone      String    @default("Asia/Kolkata")
  language      String    @default("en")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("user_profiles")
}

model NutritionistProfile {
  id                String   @id @default(uuid())
  userId            String   @unique @map("user_id")
  registrationNumber String?  @map("registration_number")
  qualifications    String[]
  specializations   String[]
  experience        Int      // in years
  aboutMe           String?  @map("about_me")
  consultationFee   Float    @map("consultation_fee")
  languages         String[]
  availability      Json?    // Weekly availability schedule
  rating            Float    @default(0)
  totalReviews      Int      @default(0) @map("total_reviews")
  isActive          Boolean  @default(true) @map("is_active")
  createdAt         DateTime @default(now()) @map("created_at")
  updatedAt         DateTime @updatedAt @map("updated_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("nutritionist_profiles")
}

model Program {
  id              String      @id @default(uuid())
  name            String
  slug            String      @unique
  type            ProgramType
  description     String
  shortDescription String?    @map("short_description")
  duration        Int         // in days
  price           Float
  discountedPrice Float?      @map("discounted_price")
  currency        String      @default("INR")
  features        String[]
  includes        Json?       // Detailed list of what's included
  outcomes        String[]    // Expected outcomes
  whoIsItFor      String[]    @map("who_is_it_for")
  image           String?
  isActive        Boolean     @default(true) @map("is_active")
  isFeatured      Boolean     @default(false) @map("is_featured")
  order           Int         @default(0)
  metadata        Json?
  createdAt       DateTime    @default(now()) @map("created_at")
  updatedAt       DateTime    @updatedAt @map("updated_at")

  // Relations
  consultations Consultation[]
  journeys      UserJourney[]
  reviews       ProgramReview[]

  @@map("programs")
  @@index([slug])
  @@index([type])
}

model Consultation {
  id               String             @id @default(uuid())
  userId           String             @map("user_id")
  nutritionistId   String             @map("nutritionist_id")
  programId        String?            @map("program_id")
  scheduledAt      DateTime           @map("scheduled_at")
  duration         Int                // in minutes
  status           ConsultationStatus @default(SCHEDULED)
  meetingLink      String?            @map("meeting_link")
  meetingId        String?            @map("meeting_id")
  notes            String?
  internalNotes    String?            @map("internal_notes")
  recordingUrl     String?            @map("recording_url")
  prescription     Json?              // Structured prescription data
  followUpDate     DateTime?          @map("follow_up_date")
  completedAt      DateTime?          @map("completed_at")
  cancelledAt      DateTime?          @map("cancelled_at")
  cancellationReason String?          @map("cancellation_reason")
  createdAt        DateTime           @default(now()) @map("created_at")
  updatedAt        DateTime           @updatedAt @map("updated_at")

  // Relations
  user         User     @relation(fields: [userId], references: [id])
  nutritionist User     @relation("NutritionistConsultations", fields: [nutritionistId], references: [id])
  program      Program? @relation(fields: [programId], references: [id])
  payment      Payment?
  reminders    ConsultationReminder[]

  @@map("consultations")
  @@index([userId])
  @@index([nutritionistId])
  @@index([scheduledAt])
  @@index([status])
}

model ConsultationReminder {
  id              String       @id @default(uuid())
  consultationId  String       @map("consultation_id")
  type            String       // email, sms, whatsapp
  scheduledAt     DateTime     @map("scheduled_at")
  sentAt          DateTime?    @map("sent_at")
  status          String       // pending, sent, failed
  createdAt       DateTime     @default(now()) @map("created_at")

  // Relations
  consultation Consultation @relation(fields: [consultationId], references: [id], onDelete: Cascade)

  @@map("consultation_reminders")
  @@index([consultationId])
  @@index([scheduledAt])
}

model Payment {
  id                  String        @id @default(uuid())
  userId              String        @map("user_id")
  consultationId      String?       @unique @map("consultation_id")
  journeyId           String?       @map("journey_id")
  amount              Float
  currency            String        @default("INR")
  status              PaymentStatus @default(PENDING)
  gateway             String        // razorpay, cashfree
  gatewayOrderId      String?       @map("gateway_order_id")
  gatewayPaymentId    String?       @map("gateway_payment_id")
  gatewaySignature    String?       @map("gateway_signature")
  paymentMethod       String?       @map("payment_method")
  refundId            String?       @map("refund_id")
  refundAmount        Float?        @map("refund_amount")
  refundedAt          DateTime?     @map("refunded_at")
  metadata            Json?
  invoiceNumber       String?       @unique @map("invoice_number")
  invoiceUrl          String?       @map("invoice_url")
  receiptUrl          String?       @map("receipt_url")
  failureReason       String?       @map("failure_reason")
  createdAt           DateTime      @default(now()) @map("created_at")
  updatedAt           DateTime      @updatedAt @map("updated_at")

  // Relations
  user         User          @relation(fields: [userId], references: [id])
  consultation Consultation? @relation(fields: [consultationId], references: [id])
  journey      UserJourney?  @relation(fields: [journeyId], references: [id])

  @@map("payments")
  @@index([userId])
  @@index([status])
  @@index([gatewayOrderId])
  @@index([invoiceNumber])
}

model UserJourney {
  id            String    @id @default(uuid())
  userId        String    @map("user_id")
  programId     String    @map("program_id")
  startDate     DateTime  @map("start_date")
  endDate       DateTime? @map("end_date")
  status        String    @default("ACTIVE") // ACTIVE, PAUSED, COMPLETED, CANCELLED
  progress      Json?     // Milestone tracking
  measurements  Json?     // Weight, BMI, other health metrics over time
  mealPlans     Json?     @map("meal_plans")
  supplements   Json?
  notes         String?
  completedAt   DateTime? @map("completed_at")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  // Relations
  user         User          @relation(fields: [userId], references: [id])
  program      Program       @relation(fields: [programId], references: [id])
  payments     Payment[]
  checkIns     JourneyCheckIn[]
  mealEntries  MealEntry[]

  @@map("user_journeys")
  @@index([userId])
  @@index([programId])
  @@index([status])
}

model JourneyCheckIn {
  id          String      @id @default(uuid())
  journeyId   String      @map("journey_id")
  date        DateTime
  weight      Float?
  energy      Int?        // 1-10 scale
  mood        Int?        // 1-10 scale
  sleep       Float?      // hours
  exercise    Int?        // minutes
  water       Float?      // liters
  symptoms    String[]
  notes       String?
  photos      String[]    // URLs
  createdAt   DateTime    @default(now()) @map("created_at")

  // Relations
  journey UserJourney @relation(fields: [journeyId], references: [id], onDelete: Cascade)

  @@map("journey_check_ins")
  @@index([journeyId])
  @@index([date])
}

model MealEntry {
  id          String      @id @default(uuid())
  journeyId   String      @map("journey_id")
  date        DateTime
  mealType    String      @map("meal_type") // breakfast, lunch, dinner, snack
  foods       Json        // Array of food items with quantities
  calories    Float?
  protein     Float?      // in grams
  carbs       Float?      // in grams
  fat         Float?      // in grams
  fiber       Float?      // in grams
  notes       String?
  photo       String?
  createdAt   DateTime    @default(now()) @map("created_at")

  // Relations
  journey UserJourney @relation(fields: [journeyId], references: [id], onDelete: Cascade)

  @@map("meal_entries")
  @@index([journeyId])
  @@index([date])
}

model Quiz {
  id          String      @id @default(uuid())
  type        QuizType
  title       String
  description String?
  questions   Json        // Array of questions with options
  scoring     Json        // Scoring logic
  isActive    Boolean     @default(true) @map("is_active")
  createdAt   DateTime    @default(now()) @map("created_at")
  updatedAt   DateTime    @updatedAt @map("updated_at")

  // Relations
  results QuizResult[]

  @@map("quizzes")
  @@index([type])
}

model QuizResult {
  id              String   @id @default(uuid())
  userId          String?  @map("user_id")
  quizId          String   @map("quiz_id")
  quizType        QuizType @map("quiz_type")
  responses       Json     // User's answers
  score           Int?
  analysis        Json?    // Detailed analysis
  recommendations Json?    // Program/action recommendations
  ipAddress       String?  @map("ip_address")
  userAgent       String?  @map("user_agent")
  completedAt     DateTime @default(now()) @map("completed_at")

  // Relations
  user User? @relation(fields: [userId], references: [id])
  quiz Quiz  @relation(fields: [quizId], references: [id])

  @@map("quiz_results")
  @@index([userId])
  @@index([quizId])
  @@index([quizType])
}

model BlogPost {
  id            String    @id @default(uuid())
  title         String
  slug          String    @unique
  excerpt       String?
  content       String    @db.Text
  featuredImage String?   @map("featured_image")
  author        String
  category      String
  tags          String[]
  readTime      Int?      @map("read_time") // in minutes
  isPublished   Boolean   @default(false) @map("is_published")
  publishedAt   DateTime? @map("published_at")
  seoTitle      String?   @map("seo_title")
  seoDescription String?  @map("seo_description")
  seoKeywords   String[]  @map("seo_keywords")
  viewCount     Int       @default(0) @map("view_count")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  @@map("blog_posts")
  @@index([slug])
  @@index([category])
  @@index([isPublished])
}

model Resource {
  id            String   @id @default(uuid())
  title         String
  description   String?
  type          String   // pdf, video, calculator, tracker
  category      String
  fileUrl       String?  @map("file_url")
  thumbnailUrl  String?  @map("thumbnail_url")
  isPublic      Boolean  @default(true) @map("is_public")
  requiresAuth  Boolean  @default(false) @map("requires_auth")
  downloadCount Int      @default(0) @map("download_count")
  tags          String[]
  metadata      Json?
  createdAt     DateTime @default(now()) @map("created_at")
  updatedAt     DateTime @updatedAt @map("updated_at")

  @@map("resources")
  @@index([type])
  @@index([category])
}

model Document {
  id           String   @id @default(uuid())
  userId       String   @map("user_id")
  type         String   // medical_report, prescription, meal_plan, etc
  title        String
  description  String?
  fileUrl      String   @map("file_url")
  fileSize     Int      @map("file_size") // in bytes
  mimeType     String   @map("mime_type")
  isArchived   Boolean  @default(false) @map("is_archived")
  metadata     Json?
  uploadedAt   DateTime @default(now()) @map("uploaded_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("documents")
  @@index([userId])
  @@index([type])
}

model Notification {
  id         String    @id @default(uuid())
  userId     String    @map("user_id")
  type       String    // email, sms, whatsapp, in-app
  category   String    // consultation, payment, journey, system
  title      String
  content    String
  data       Json?     // Additional data for the notification
  status     String    @default("PENDING") // PENDING, SENT, FAILED
  readAt     DateTime? @map("read_at")
  sentAt     DateTime? @map("sent_at")
  error      String?
  createdAt  DateTime  @default(now()) @map("created_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("notifications")
  @@index([userId])
  @@index([status])
  @@index([type])
}

model RefreshToken {
  id          String   @id @default(uuid())
  userId      String   @map("user_id")
  token       String   @unique
  expiresAt   DateTime @map("expires_at")
  createdAt   DateTime @default(now()) @map("created_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("refresh_tokens")
  @@index([token])
  @@index([userId])
}

model ProgramReview {
  id         String   @id @default(uuid())
  programId  String   @map("program_id")
  userId     String   @map("user_id")
  rating     Int      // 1-5
  title      String?
  comment    String?
  isVerified Boolean  @default(false) @map("is_verified")
  createdAt  DateTime @default(now()) @map("created_at")
  updatedAt  DateTime @updatedAt @map("updated_at")

  // Relations
  program Program @relation(fields: [programId], references: [id])

  @@map("program_reviews")
  @@unique([programId, userId])
  @@index([programId])
}

model AuditLog {
  id         String   @id @default(uuid())
  userId     String?  @map("user_id")
  action     String   // CREATE, UPDATE, DELETE, LOGIN, etc
  entity     String   // user, consultation, payment, etc
  entityId   String?  @map("entity_id")
  changes    Json?    // Before and after values
  ipAddress  String?  @map("ip_address")
  userAgent  String?  @map("user_agent")
  createdAt  DateTime @default(now()) @map("created_at")

  @@map("audit_logs")
  @@index([userId])
  @@index([entity])
  @@index([action])
  @@index([createdAt])
}
```

#### 2. Database Initialization Script
```sql
-- infrastructure/docker/postgres/init.sql
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create indexes for text search
CREATE INDEX idx_blog_posts_title_trgm ON blog_posts USING gin (title gin_trgm_ops);
CREATE INDEX idx_blog_posts_content_trgm ON blog_posts USING gin (content gin_trgm_ops);
CREATE INDEX idx_resources_title_trgm ON resources USING gin (title gin_trgm_ops);

-- Create functions for updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_profiles_updated_at BEFORE UPDATE ON user_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add more triggers for other tables...
```

## Week 2: Core Services & Authentication

### Day 1-2: Authentication Service Implementation

#### 1. Create Auth Service Structure
```bash
# Create auth service
cd services/auth
npm init -y
npm install express bcrypt jsonwebtoken speakeasy qrcode passport passport-jwt passport-local
npm install -D @types/express @types/bcrypt @types/jsonwebtoken @types/passport @types/passport-jwt @types/passport-local typescript nodemon

# Create folder structure
mkdir -p src/{controllers,services,middleware,routes,utils,validators,types}
touch src/index.ts
```

#### 2. Auth Service Configuration
```typescript
// services/auth/src/config/index.ts
import { config } from 'dotenv';
import path from 'path';

// Load environment variables
config({ path: path.join(__dirname, '../../../../.env') });

export const authConfig = {
  port: process.env.AUTH_SERVICE_PORT || 4001,
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    algorithm: 'HS256' as const,
  },
  bcrypt: {
    saltRounds: 12,
  },
  twoFA: {
    appName: process.env.TWO_FA_APP_NAME || 'NutritionPlatform',
    window: 1, // Allow 30 seconds time window
  },
  email: {
    verificationExpiry: 24 * 60 * 60 * 1000, // 24 hours
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5, // Limit each IP to 5 requests per windowMs
  },
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true,
  },
};
```

#### 3. Auth Types & Interfaces
```typescript
// services/auth/src/types/auth.types.ts
export interface JWTPayload {
  userId: string;
  email: string;
  role: UserRole;
  sessionId?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface RegisterDTO {
  email: string;
  password: string;
  phone?: string;
  firstName: string;
  lastName: string;
  acceptTerms: boolean;
}

export interface LoginDTO {
  email: string;
  password: string;
  twoFactorCode?: string;
}

export interface VerifyEmailDTO {
  token: string;
}

export interface Enable2FADTO {
  password: string;
}

export interface Verify2FADTO {
  token: string;
}

export enum UserRole {
  USER = 'USER',
  NUTRITIONIST = 'NUTRITIONIST',
  ADMIN = 'ADMIN',
}

export interface SessionData {
  userId: string;
  deviceInfo: {
    userAgent: string;
    ip: string;
    device?: string;
    browser?: string;
  };
  lastActivity: Date;
}
```

#### 4. JWT Service Implementation
```typescript
// services/auth/src/services/jwt.service.ts
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { authConfig } from '../config';
import { JWTPayload, AuthTokens } from '../types/auth.types';
import { redisClient } from '../utils/redis';
import { prisma } from '@nutrition/database';

export class JWTService {
  private static readonly ACCESS_TOKEN_PREFIX = 'access_token:';
  private static readonly REFRESH_TOKEN_PREFIX = 'refresh_token:';
  private static readonly BLACKLIST_PREFIX = 'blacklist:';

  static async generateTokens(payload: JWTPayload): Promise<AuthTokens> {
    const sessionId = uuidv4();
    const tokenPayload = { ...payload, sessionId };

    // Generate access token
    const accessToken = jwt.sign(
      tokenPayload,
      authConfig.jwt.secret,
      {
        expiresIn: authConfig.jwt.expiresIn,
        algorithm: authConfig.jwt.algorithm,
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { userId: payload.userId, sessionId },
      authConfig.jwt.refreshSecret,
      {
        expiresIn: authConfig.jwt.refreshExpiresIn,
        algorithm: authConfig.jwt.algorithm,
      }
    );

    // Store refresh token in database
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    await prisma.refreshToken.create({
      data: {
        userId: payload.userId,
        token: refreshToken,
        expiresAt,
      },
    });

    // Store session in Redis
    await redisClient.setex(
      `${this.ACCESS_TOKEN_PREFIX}${sessionId}`,
      15 * 60, // 15 minutes
      JSON.stringify(payload)
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: 15 * 60, // 15 minutes in seconds
    };
  }

  static async verifyAccessToken(token: string): Promise<JWTPayload> {
    try {
      // Check if token is blacklisted
      const isBlacklisted = await redisClient.get(`${this.BLACKLIST_PREFIX}${token}`);
      if (isBlacklisted) {
        throw new Error('Token is blacklisted');
      }

      const decoded = jwt.verify(token, authConfig.jwt.secret) as JWTPayload & { sessionId: string };
      
      // Verify session exists
      const session = await redisClient.get(`${this.ACCESS_TOKEN_PREFIX}${decoded.sessionId}`);
      if (!session) {
        throw new Error('Session not found');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  static async verifyRefreshToken(token: string): Promise<{ userId: string; sessionId: string }> {
    try {
      const decoded = jwt.verify(token, authConfig.jwt.refreshSecret) as { userId: string; sessionId: string };
      
      // Check if refresh token exists in database
      const refreshToken = await prisma.refreshToken.findUnique({
        where: { token },
      });

      if (!refreshToken || refreshToken.expiresAt < new Date()) {
        throw new Error('Invalid refresh token');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  static async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const { userId } = await this.verifyRefreshToken(refreshToken);

    // Get user details
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Delete old refresh token
    await prisma.refreshToken.delete({
      where: { token: refreshToken },
    });

    // Generate new tokens
    return this.generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role,
    });
  }

  static async revokeToken(token: string, sessionId?: string): Promise<void> {
    // Add token to blacklist
    const decoded = jwt.decode(token) as any;
    if (decoded && decoded.exp) {
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await redisClient.setex(`${this.BLACKLIST_PREFIX}${token}`, ttl, '1');
      }
    }

    // Remove session if provided
    if (sessionId) {
      await redisClient.del(`${this.ACCESS_TOKEN_PREFIX}${sessionId}`);
    }
  }

  static async revokeAllUserTokens(userId: string): Promise<void> {
    // Delete all refresh tokens
    await prisma.refreshToken.deleteMany({
      where: { userId },
    });

    // Note: Access tokens will expire naturally or need to track sessions differently
  }
}
```

#### 5. Password Service
```typescript
// services/auth/src/services/password.service.ts
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { authConfig } from '../config';
import { redisClient } from '../utils/redis';

export class PasswordService {
  private static readonly RESET_TOKEN_PREFIX = 'password_reset:';
  private static readonly RESET_TOKEN_EXPIRY = 3600; // 1 hour

  static async hash(password: string): Promise<string> {
    return bcrypt.hash(password, authConfig.bcrypt.saltRounds);
  }

  static async compare(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  static validateStrength(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async generateResetToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Store in Redis with expiry
    await redisClient.setex(
      `${this.RESET_TOKEN_PREFIX}${hashedToken}`,
      this.RESET_TOKEN_EXPIRY,
      userId
    );

    return token;
  }

  static async verifyResetToken(token: string): Promise<string | null> {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const userId = await redisClient.get(`${this.RESET_TOKEN_PREFIX}${hashedToken}`);

    if (!userId) {
      return null;
    }

    // Delete token after verification
    await redisClient.del(`${this.RESET_TOKEN_PREFIX}${hashedToken}`);
    return userId;
  }
}
```

#### 6. Two-Factor Authentication Service
```typescript
// services/auth/src/services/twoFA.service.ts
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { authConfig } from '../config';
import { prisma } from '@nutrition/database';

export class TwoFAService {
  static generateSecret(email: string): speakeasy.GeneratedSecret {
    return speakeasy.generateSecret({
      name: `${authConfig.twoFA.appName} (${email})`,
      length: 32,
    });
  }

  static async generateQRCode(secret: speakeasy.GeneratedSecret): Promise<string> {
    return QRCode.toDataURL(secret.otpauth_url!);
  }

  static verifyToken(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: authConfig.twoFA.window,
    });
  }

  static async enableTwoFA(userId: string, secret: string): Promise<string[]> {
    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      Math.random().toString(36).substring(2, 10).toUpperCase()
    );

    // Hash backup codes
    const hashedCodes = await Promise.all(
      backupCodes.map(code => bcrypt.hash(code, 10))
    );

    // Update user
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFASecret: secret,
        twoFAEnabled: true,
        twoFABackupCodes: hashedCodes,
      },
    });

    return backupCodes;
  }

  static async disableTwoFA(userId: string): Promise<void> {
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFASecret: null,
        twoFAEnabled: false,
        twoFABackupCodes: [],
      },
    });
  }

  static async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { twoFABackupCodes: true },
    });

    if (!user || !user.twoFABackupCodes) {
      return false;
    }

    // Check each backup code
    for (let i = 0; i < user.twoFABackupCodes.length; i++) {
      const isValid = await bcrypt.compare(code, user.twoFABackupCodes[i]);
      if (isValid) {
        // Remove used backup code
        const newCodes = [...user.twoFABackupCodes];
        newCodes.splice(i, 1);

        await prisma.user.update({
          where: { id: userId },
          data: { twoFABackupCodes: newCodes },
        });

        return true;
      }
    }

    return false;
  }
}
```

### Day 3-4: Auth Controllers & Middleware

#### 1. Auth Controller Implementation
```typescript
// services/auth/src/controllers/auth.controller.ts
import { Request, Response, NextFunction } from 'express';
import { prisma } from '@nutrition/database';
import { JWTService } from '../services/jwt.service';
import { PasswordService } from '../services/password.service';
import { TwoFAService } from '../services/twoFA.service';
import { EmailService } from '../services/email.service';
import { RegisterDTO, LoginDTO } from '../types/auth.types';
import { validateRegister, validateLogin } from '../validators/auth.validator';
import { AppError } from '../utils/errors';
import { auditLog } from '../utils/audit';

export class AuthController {
  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const body: RegisterDTO = req.body;

      // Validate input
      const validation = validateRegister(body);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      // Check if user exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { email: body.email },
            { phone: body.phone || undefined },
          ],
        },
      });

      if (existingUser) {
        throw new AppError('User already exists', 409);
      }

      // Validate password strength
      const passwordValidation = PasswordService.validateStrength(body.password);
      if (!passwordValidation.valid) {
        throw new AppError('Weak password', 400, passwordValidation.errors);
      }

      // Hash password
      const passwordHash = await PasswordService.hash(body.password);

      // Create user in transaction
      const user = await prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: {
            email: body.email,
            phone: body.phone,
            passwordHash,
            profile: {
              create: {
                firstName: body.firstName,
                lastName: body.lastName,
              },
            },
          },
          include: {
            profile: true,
          },
        });

        // Create audit log
        await auditLog({
          userId: newUser.id,
          action: 'REGISTER',
          entity: 'user',
          entityId: newUser.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        });

        return newUser;
      });

      // Send verification email
      const verificationToken = await EmailService.sendVerificationEmail(
        user.email,
        user.profile!.firstName
      );

      // Generate tokens
      const tokens = await JWTService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful. Please verify your email.',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.profile!.firstName,
            lastName: user.profile!.lastName,
            emailVerified: user.emailVerified,
          },
          tokens,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const body: LoginDTO = req.body;

      // Validate input
      const validation = validateLogin(body);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      // Find user
      const user = await prisma.user.findUnique({
        where: { email: body.email },
        include: {
          profile: true,
        },
      });

      if (!user) {
        throw new AppError('Invalid credentials', 401);
      }

      // Verify password
      const isValidPassword = await PasswordService.compare(
        body.password,
        user.passwordHash
      );

      if (!isValidPassword) {
        // Log failed attempt
        await auditLog({
          userId: user.id,
          action: 'LOGIN_FAILED',
          entity: 'user',
          entityId: user.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        });

        throw new AppError('Invalid credentials', 401);
      }

      // Check if 2FA is enabled
      if (user.twoFAEnabled) {
        if (!body.twoFactorCode) {
          return res.status(200).json({
            success: true,
            message: 'Two-factor authentication required',
            data: {
              requiresTwoFactor: true,
              userId: user.id,
            },
          });
        }

        // Verify 2FA code
        const isValid2FA = TwoFAService.verifyToken(
          user.twoFASecret!,
          body.twoFactorCode
        );

        if (!isValid2FA) {
          // Check backup code
          const isValidBackup = await TwoFAService.verifyBackupCode(
            user.id,
            body.twoFactorCode
          );

          if (!isValidBackup) {
            throw new AppError('Invalid two-factor code', 401);
          }
        }
      }

      // Update last login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });

      // Generate tokens
      const tokens = await JWTService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      // Log successful login
      await auditLog({
        userId: user.id,
        action: 'LOGIN',
        entity: 'user',
        entityId: user.id,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.profile!.firstName,
            lastName: user.profile!.lastName,
            emailVerified: user.emailVerified,
            twoFAEnabled: user.twoFAEnabled,
          },
          tokens,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async logout(req: Request, res: Response, next: NextFunction) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      const { userId, sessionId } = req.user!;

      if (token) {
        await JWTService.revokeToken(token, sessionId);
      }

      // Log logout
      await auditLog({
        userId,
        action: 'LOGOUT',
        entity: 'user',
        entityId: userId,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      res.json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      next(error);
    }
  }

  static async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw new AppError('Refresh token required', 400);
      }

      const tokens = await JWTService.refreshTokens(refreshToken);

      res.json({
        success: true,
        data: { tokens },
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.body;

      const userId = await EmailService.verifyEmailToken(token);
      if (!userId) {
        throw new AppError('Invalid or expired token', 400);
      }

      await prisma.user.update({
        where: { id: userId },
        data: { emailVerified: true },
      });

      res.json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async enable2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password } = req.body;

      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const isValidPassword = await PasswordService.compare(
        password,
        user.passwordHash
      );

      if (!isValidPassword) {
        throw new AppError('Invalid password', 401);
      }

      // Generate secret
      const secret = TwoFAService.generateSecret(user.email);
      const qrCode = await TwoFAService.generateQRCode(secret);

      // Store secret temporarily
      await redisClient.setex(
        `2fa_setup:${userId}`,
        600, // 10 minutes
        secret.base32
      );

      res.json({
        success: true,
        data: {
          secret: secret.base32,
          qrCode,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async confirm2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { token } = req.body;

      // Get temporary secret
      const secret = await redisClient.get(`2fa_setup:${userId}`);
      if (!secret) {
        throw new AppError('2FA setup expired', 400);
      }

      // Verify token
      const isValid = TwoFAService.verifyToken(secret, token);
      if (!isValid) {
        throw new AppError('Invalid token', 400);
      }

      // Enable 2FA and get backup codes
      const backupCodes = await TwoFAService.enableTwoFA(userId, secret);

      // Clean up temporary secret
      await redisClient.del(`2fa_setup:${userId}`);

      res.json({
        success: true,
        message: '2FA enabled successfully',
        data: {
          backupCodes,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async disable2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password, token } = req.body;

      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const isValidPassword = await PasswordService.compare(
        password,
        user.passwordHash
      );

      if (!isValidPassword) {
        throw new AppError('Invalid password', 401);
      }

      // Verify 2FA token
      if (user.twoFAEnabled && user.twoFASecret) {
        const isValid = TwoFAService.verifyToken(user.twoFASecret, token);
        if (!isValid) {
          throw new AppError('Invalid 2FA token', 401);
        }
      }

      // Disable 2FA
      await TwoFAService.disableTwoFA(userId);

      res.json({
        success: true,
        message: '2FA disabled successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body;

      const user = await prisma.user.findUnique({
        where: { email },
        include: { profile: true },
      });

      if (!user) {
        // Don't reveal if user exists
        return res.json({
          success: true,
          message: 'If the email exists, a reset link has been sent',
        });
      }

      // Generate reset token
      const resetToken = await PasswordService.generateResetToken(user.id);

      // Send reset email
      await EmailService.sendPasswordResetEmail(
        user.email,
        user.profile!.firstName,
        resetToken
      );

      res.json({
        success: true,
        message: 'If the email exists, a reset link has been sent',
      });
    } catch (error) {
      next(error);
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { token, password } = req.body;

      // Verify token
      const userId = await PasswordService.verifyResetToken(token);
      if (!userId) {
        throw new AppError('Invalid or expired token', 400);
      }

      // Validate password
      const passwordValidation = PasswordService.validateStrength(password);
      if (!passwordValidation.valid) {
        throw new AppError('Weak password', 400, passwordValidation.errors);
      }

      // Hash and update password
      const passwordHash = await PasswordService.hash(password);
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash },
      });

      // Revoke all tokens
      await JWTService.revokeAllUserTokens(userId);

      res.json({
        success: true,
        message: 'Password reset successful',
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Auth Middleware
```typescript
// services/auth/src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { JWTService } from '../services/jwt.service';
import { AppError } from '../utils/errors';
import { UserRole } from '../types/auth.types';

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        role: UserRole;
        sessionId?: string;
      };
    }
  }
}

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError('No token provided', 401);
    }

    const token = authHeader.split(' ')[1];
    const payload = await JWTService.verifyAccessToken(token);

    req.user = payload;
    next();
  } catch (error) {
    next(new AppError('Invalid token', 401));
  }
};

export const authorize = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Unauthorized', 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(new AppError('Forbidden', 403));
    }

    next();
  };
};

export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    const token = authHeader.split(' ')[1];
    const payload = await JWTService.verifyAccessToken(token);

    req.user = payload;
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};
```

### Day 5-7: Email Service & Templates

#### 1. Email Service Implementation
```typescript
// services/auth/src/services/email.service.ts
import nodemailer from 'nodemailer';
import mjml2html from 'mjml';
import { redisClient } from '../utils/redis';
import { authConfig } from '../config';
import crypto from 'crypto';

export class EmailService {
  private static transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  private static readonly VERIFICATION_PREFIX = 'email_verify:';
  private static readonly VERIFICATION_EXPIRY = 24 * 60 * 60; // 24 hours

  static async sendVerificationEmail(
    email: string,
    firstName: string
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Store token with user email
    await redisClient.setex(
      `${this.VERIFICATION_PREFIX}${hashedToken}`,
      this.VERIFICATION_EXPIRY,
      email
    );

    const verificationUrl = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Verify Your Email</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
          <mj-attributes>
            <mj-all font-family="Inter, Arial, sans-serif" />
            <mj-text font-size="16px" color="#333333" line-height="24px" />
            <mj-section background-color="#f4f4f4" />
          </mj-attributes>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="28px" font-weight="700" color="#1a1a1a" align="center">
                Welcome to Nutrition Platform!
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Hi ${firstName},
              </mj-text>
              <mj-text>
                Thank you for signing up! Please verify your email address to get started on your wellness journey.
              </mj-text>
              <mj-spacer height="30px" />
              <mj-button 
                background-color="#10b981" 
                color="#ffffff" 
                font-size="16px" 
                font-weight="600"
                padding="15px 30px"
                border-radius="6px"
                href="${verificationUrl}"
              >
                Verify Email Address
              </mj-button>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                Or copy and paste this link into your browser:
              </mj-text>
              <mj-text font-size="14px" color="#10b981">
                ${verificationUrl}
              </mj-text>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                This link will expire in 24 hours. If you didn't create an account, you can safely ignore this email.
              </mj-text>
            </mj-column>
          </mj-section>
          <mj-section padding="20px">
            <mj-column>
              <mj-text align="center" font-size="14px" color="#666666">
                © 2024 Nutrition Platform. All rights reserved.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Verify Your Email - Nutrition Platform',
      html,
    });

    return token;
  }

  static async verifyEmailToken(token: string): Promise<string | null> {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const email = await redisClient.get(`${this.VERIFICATION_PREFIX}${hashedToken}`);

    if (!email) {
      return null;
    }

    // Delete token after verification
    await redisClient.del(`${this.VERIFICATION_PREFIX}${hashedToken}`);
    return email;
  }

  static async sendPasswordResetEmail(
    email: string,
    firstName: string,
    resetToken: string
  ): Promise<void> {
    const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}`;

    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Reset Your Password</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
          <mj-attributes>
            <mj-all font-family="Inter, Arial, sans-serif" />
            <mj-text font-size="16px" color="#333333" line-height="24px" />
            <mj-section background-color="#f4f4f4" />
          </mj-attributes>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="28px" font-weight="700" color="#1a1a1a" align="center">
                Reset Your Password
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Hi ${firstName},
              </mj-text>
              <mj-text>
                We received a request to reset your password. Click the button below to create a new password.
              </mj-text>
              <mj-spacer height="30px" />
              <mj-button 
                background-color="#10b981" 
                color="#ffffff" 
                font-size="16px" 
                font-weight="600"
                padding="15px 30px"
                border-radius="6px"
                href="${resetUrl}"
              >
                Reset Password
              </mj-button>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text font-size="14px" color="#dc2626" font-weight="600">
                Security Tip: Never share your password with anyone, including our support team.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Reset Your Password - Nutrition Platform',
      html,
    });
  }

  static async sendWelcomeEmail(
    email: string,
    firstName: string
  ): Promise<void> {
    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Welcome to Your Wellness Journey</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="32px" font-weight="700" color="#1a1a1a" align="center">
                Welcome, ${firstName}! 🌱
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text font-size="18px" align="center" color="#666666">
                Your journey to better health starts now
              </mj-text>
              <mj-spacer height="40px" />
              <mj-text>
                We're thrilled to have you join our community! Here's what you can do next:
              </mj-text>
              <mj-spacer height="20px" />
              
              <!-- Getting Started Steps -->
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    🎯 1. Take the Health Assessment Quiz
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    Get personalized recommendations based on your health goals
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/quiz/health-assessment"
                  >
                    Start Quiz
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="15px" />
              
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    📅 2. Book Your Free Discovery Call
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    20-minute consultation to discuss your wellness goals
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/book-consultation"
                  >
                    Book Now
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="15px" />
              
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    📚 3. Explore Our Resources
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    Free guides, meal plans, and health tips
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/resources"
                  >
                    Browse Resources
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="40px" />
              
              <mj-text align="center" font-size="14px" color="#666666">
                Questions? Reply to this email or reach out to us at support@nutritionplatform.com
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Welcome to Your Wellness Journey! 🌱',
      html,
    });
  }

  static async send2FAEmail(
    email: string,
    firstName: string,
    code: string
  ): Promise<void> {
    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Your Login Code</mj-title>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="24px" font-weight="700" align="center">
                Your Login Code
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>Hi ${firstName},</mj-text>
              <mj-text>
                Here's your temporary login code:
              </mj-text>
              <mj-spacer height="20px" />
              <mj-wrapper background-color="#f8fafc" padding="20px" border-radius="6px">
                <mj-column>
                  <mj-text font-size="32px" font-weight="700" align="center" letter-spacing="8px">
                    ${code}
                  </mj-text>
                </mj-column>
              </mj-wrapper>
              <mj-spacer height="20px" />
              <mj-text font-size="14px" color="#666666">
                This code will expire in 5 minutes. If you didn't request this, please ignore this email.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: `Your Login Code: ${code}`,
      html,
    });
  }
}
```

## Week 3: User Service & Profile Management

### Day 1-2: User Service Setup

#### 1. User Service Structure
```typescript
// services/user/src/index.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { errorHandler } from './middleware/error.middleware';
import { requestLogger } from './middleware/logger.middleware';
import { rateLimiter } from './middleware/rateLimit.middleware';
import userRoutes from './routes/user.routes';
import profileRoutes from './routes/profile.routes';
import documentRoutes from './routes/document.routes';

const app = express();
const PORT = process.env.USER_SERVICE_PORT || 4002;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);
app.use(rateLimiter);

// Routes
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/profiles', profileRoutes);
app.use('/api/v1/documents', documentRoutes);

// Error handling
app.use(errorHandler);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'user-service' });
});

app.listen(PORT, () => {
  console.log(`User Service running on port ${PORT}`);
});
```

#### 2. User Controller
```typescript
// services/user/src/controllers/user.controller.ts
import { Request, Response, NextFunction } from 'express';
import { prisma } from '@nutrition/database';
import { UserService } from '../services/user.service';
import { ProfileService } from '../services/profile.service';
import { AppError } from '../utils/errors';
import { uploadToStorage } from '../utils/storage';

export class UserController {
  static async getProfile(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const profile = await ProfileService.getFullProfile(userId);

      if (!profile) {
        throw new AppError('Profile not found', 404);
      }

      res.json({
        success: true,
        data: profile,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateProfile(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const updates = req.body;

      // Validate updates
      const validation = ProfileService.validateProfileUpdate(updates);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      const updatedProfile = await ProfileService.updateProfile(userId, updates);

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: updatedProfile,
      });
    } catch (error) {
      next(error);
    }
  }

  static async uploadAvatar(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const file = req.file;

      if (!file) {
        throw new AppError('No file uploaded', 400);
      }

      // Validate file
      const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid file type', 400);
      }

      if (file.size > 5 * 1024 * 1024) { // 5MB
        throw new AppError('File too large', 400);
      }

      // Process and upload image
      const avatarUrl = await ProfileService.updateAvatar(userId, file);

      res.json({
        success: true,
        message: 'Avatar updated successfully',
        data: { avatarUrl },
      });
    } catch (error) {
      next(error);
    }
  }

  static async getMedicalHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const history = await UserService.getMedicalHistory(userId);

      res.json({
        success: true,
        data: history,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateMedicalHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const medicalData = req.body;

      const updated = await UserService.updateMedicalHistory(userId, medicalData);

      res.json({
        success: true,
        message: 'Medical history updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getHealthMetrics(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { startDate, endDate } = req.query;

      const metrics = await UserService.getHealthMetrics(
        userId,
        startDate as string,
        endDate as string
      );

      res.json({
        success: true,
        data: metrics,
      });
    } catch (error) {
      next(error);
    }
  }

  static async addHealthMetric(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const metricData = req.body;

      const metric = await UserService.addHealthMetric(userId, metricData);

      res.json({
        success: true,
        message: 'Health metric added successfully',
        data: metric,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const preferences = await UserService.getPreferences(userId);

      res.json({
        success: true,
        data: preferences,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updatePreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const preferences = req.body;

      const updated = await UserService.updatePreferences(userId, preferences);

      res.json({
        success: true,
        message: 'Preferences updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteAccount(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password, reason } = req.body;

      // Verify password
      const isValid = await UserService.verifyPassword(userId, password);
      if (!isValid) {
        throw new AppError('Invalid password', 401);
      }

      // Schedule account deletion
      await UserService.scheduleAccountDeletion(userId, reason);

      res.json({
        success: true,
        message: 'Account deletion scheduled. You have 30 days to cancel this request.',
      });
    } catch (error) {
      next(error);
    }
  }

  static async exportUserData(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      // Generate export
      const exportUrl = await UserService.exportUserData(userId);

      res.json({
        success: true,
        message: 'Your data export is ready',
        data: { downloadUrl: exportUrl },
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 3. Profile Service
```typescript
// services/user/src/services/profile.service.ts
import { prisma } from '@nutrition/database';
import sharp from 'sharp';
import { uploadToStorage, deleteFromStorage } from '../utils/storage';
import { calculateBMI, calculateBMR } from '../utils/health.calculations';

export class ProfileService {
  static async getFullProfile(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        profile: true,
        journeys: {
          include: {
            program: true,
          },
          orderBy: {
            startDate: 'desc',
          },
          take: 1,
        },
        consultations: {
          where: {
            status: 'COMPLETED',
          },
          orderBy: {
            completedAt: 'desc',
          },
          take: 5,
        },
      },
    });

    if (!user) {
      return null;
    }

    // Calculate additional metrics
    const metrics = user.profile
      ? {
          bmi: calculateBMI(user.profile.weight, user.profile.height),
          bmr: calculateBMR(
            user.profile.weight,
            user.profile.height,
            user.profile.dateOfBirth,
            user.profile.gender
          ),
        }
      : null;

    return {
      ...user,
      metrics,
    };
  }

  static validateProfileUpdate(data: any) {
    const errors: string[] = [];

    if (data.height && (data.height < 50 || data.height > 300)) {
      errors.push('Height must be between 50 and 300 cm');
    }

    if (data.weight && (data.weight < 20 || data.weight > 500)) {
      errors.push('Weight must be between 20 and 500 kg');
    }

    if (data.dateOfBirth) {
      const age = new Date().getFullYear() - new Date(data.dateOfBirth).getFullYear();
      if (age < 13 || age > 120) {
        errors.push('Age must be between 13 and 120 years');
      }
    }

    if (data.phone && !/^[+]?[0-9]{10,15}$/.test(data.phone)) {
      errors.push('Invalid phone number format');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async updateProfile(userId: string, updates: any) {
    const { allergies, medications, ...profileData } = updates;

    const updatedProfile = await prisma.userProfile.update({
      where: { userId },
      data: {
        ...profileData,
        allergies: allergies ? { set: allergies } : undefined,
        medications: medications ? { set: medications } : undefined,
      },
    });

    // Update phone in user table if provided
    if (updates.phone) {
      await prisma.user.update({
        where: { id: userId },
        data: { phone: updates.phone },
      });
    }

    return updatedProfile;
  }

  static async updateAvatar(userId: string, file: Express.Multer.File) {
    // Get current avatar to delete later
    const profile = await prisma.userProfile.findUnique({
      where: { userId },
      select: { avatar: true },
    });

    // Process image
    const processedImage = await sharp(file.buffer)
      .resize(400, 400, {
        fit: 'cover',
        position: 'center',
      })
      .jpeg({ quality: 90 })
      .toBuffer();

    // Upload to storage
    const filename = `avatars/${userId}-${Date.now()}.jpg`;
    const avatarUrl = await uploadToStorage(processedImage, filename, 'image/jpeg');

    // Update profile
    await prisma.userProfile.update({
      where: { userId },
      data: { avatar: avatarUrl },
    });

    // Delete old avatar if exists
    if (profile?.avatar) {
      await deleteFromStorage(profile.avatar).catch(console.error);
    }

    return avatarUrl;
  }

  static async createInitialProfile(userId: string, data: any) {
    return prisma.userProfile.create({
      data: {
        userId,
        firstName: data.firstName,
        lastName: data.lastName,
        ...data,
      },
    });
  }
}
```

### Day 3-4: Document Management

#### 1. Document Controller
```typescript
// services/user/src/controllers/document.controller.ts
import { Request, Response, NextFunction } from 'express';
import { DocumentService } from '../services/document.service';
import { AppError } from '../utils/errors';

export class DocumentController {
  static async uploadDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { type, title, description } = req.body;
      const file = req.file;

      if (!file) {
        throw new AppError('No file uploaded', 400);
      }

      // Validate file type
      const allowedTypes = [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      ];

      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid file type', 400);
      }

      // File size limit: 10MB
      if (file.size > 10 * 1024 * 1024) {
        throw new AppError('File too large (max 10MB)', 400);
      }

      const document = await DocumentService.uploadDocument(userId, {
        type,
        title,
        description,
        file,
      });

      res.status(201).json({
        success: true,
        message: 'Document uploaded successfully',
        data: document,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocuments(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { type, page = 1, limit = 20 } = req.query;

      const documents = await DocumentService.getUserDocuments(userId, {
        type: type as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: documents,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const document = await DocumentService.getDocument(id, userId);

      if (!document) {
        throw new AppError('Document not found', 404);
      }

      res.json({
        success: true,
        data: document,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocumentUrl(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const url = await DocumentService.getSignedUrl(id, userId);

      res.json({
        success: true,
        data: { url },
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      await DocumentService.deleteDocument(id, userId);

      res.json({
        success: true,
        message: 'Document deleted successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async archiveDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      await DocumentService.archiveDocument(id, userId);

      res.json({
        success: true,
        message: 'Document archived successfully',
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Document Service
```typescript
// services/user/src/services/document.service.ts
import { prisma } from '@nutrition/database';
import { uploadToStorage, deleteFromStorage, getSignedUrl } from '../utils/storage';
import crypto from 'crypto';
import { scanFile } from '../utils/antivirus';

interface UploadDocumentDto {
  type: string;
  title: string;
  description?: string;
  file: Express.Multer.File;
}

export class DocumentService {
  static async uploadDocument(userId: string, data: UploadDocumentDto) {
    // Scan file for viruses
    const isSafe = await scanFile(data.file.buffer);
    if (!isSafe) {
      throw new Error('File failed security scan');
    }

    // Generate unique filename
    const fileExt = data.file.originalname.split('.').pop();
    const filename = `documents/${userId}/${crypto.randomBytes(16).toString('hex')}.${fileExt}`;

    // Upload to storage
    const fileUrl = await uploadToStorage(
      data.file.buffer,
      filename,
      data.file.mimetype
    );

    // Create document record
    const document = await prisma.document.create({
      data: {
        userId,
        type: data.type,
        title: data.title,
        description: data.description,
        fileUrl,
        fileSize: data.file.size,
        mimeType: data.file.mimetype,
      },
    });

    return document;
  }

  static async getUserDocuments(
    userId: string,
    options: { type?: string; page: number; limit: number }
  ) {
    const where = {
      userId,
      isArchived: false,
      ...(options.type && { type: options.type }),
    };

    const [documents, total] = await Promise.all([
      prisma.document.findMany({
        where,
        orderBy: { uploadedAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
      }),
      prisma.document.count({ where }),
    ]);

    return {
      documents,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getDocument(documentId: string, userId: string) {
    return prisma.document.findFirst({
      where: {
        id: documentId,
        userId,
      },
    });
  }

  static async getSignedUrl(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    return getSignedUrl(document.fileUrl, 3600); // 1 hour expiry
  }

  static async deleteDocument(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    // Delete from storage
    await deleteFromStorage(document.fileUrl);

    // Delete from database
    await prisma.document.delete({
      where: { id: documentId },
    });
  }

  static async archiveDocument(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    await prisma.document.update({
      where: { id: documentId },
      data: { isArchived: true },
    });
  }

  static async getDocumentsByType(userId: string, type: string) {
    return prisma.document.findMany({
      where: {
        userId,
        type,
        isArchived: false,
      },
      orderBy: { uploadedAt: 'desc' },
    });
  }
}
```

### Day 3-4: Consultation Booking Service

#### 1. Consultation Controller
```typescript
// services/consultation/src/controllers/consultation.controller.ts
import { Request, Response, NextFunction } from 'express';
import { ConsultationService } from '../services/consultation.service';
import { CalendarService } from '../services/calendar.service';
import { AppError } from '../utils/errors';

export class ConsultationController {
  static async getAvailableSlots(req: Request, res: Response, next: NextFunction) {
    try {
      const { nutritionistId, date, timezone = 'Asia/Kolkata' } = req.query;

      if (!nutritionistId || !date) {
        throw new AppError('Nutritionist ID and date are required', 400);
      }

      const slots = await CalendarService.getAvailableSlots(
        nutritionistId as string,
        new Date(date as string),
        timezone as string
      );

      res.json({
        success: true,
        data: slots,
      });
    } catch (error) {
      next(error);
    }
  }

  static async bookConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const {
        nutritionistId,
        programId,
        scheduledAt,
        duration = 60,
        notes,
        timezone = 'Asia/Kolkata',
      } = req.body;

      // Validate slot availability
      const isAvailable = await CalendarService.checkSlotAvailability(
        nutritionistId,
        new Date(scheduledAt),
        duration
      );

      if (!isAvailable) {
        throw new AppError('Selected time slot is not available', 400);
      }

      const consultation = await ConsultationService.bookConsultation({
        userId,
        nutritionistId,
        programId,
        scheduledAt: new Date(scheduledAt),
        duration,
        notes,
        timezone,
      });

      res.status(201).json({
        success: true,
        message: 'Consultation booked successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUserConsultations(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { status, page = 1, limit = 10 } = req.query;

      const consultations = await ConsultationService.getUserConsultations(userId, {
        status: status as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: consultations,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const consultation = await ConsultationService.getConsultation(id, userId);

      if (!consultation) {
        throw new AppError('Consultation not found', 404);
      }

      res.json({
        success: true,
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async rescheduleConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { scheduledAt, reason } = req.body;

      const consultation = await ConsultationService.rescheduleConsultation(
        id,
        userId,
        new Date(scheduledAt),
        reason
      );

      res.json({
        success: true,
        message: 'Consultation rescheduled successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async cancelConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { reason } = req.body;

      await ConsultationService.cancelConsultation(id, userId, reason);

      res.json({
        success: true,
        message: 'Consultation cancelled successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async joinConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const meetingInfo = await ConsultationService.getMeetingInfo(id, userId);

      res.json({
        success: true,
        data: meetingInfo,
      });
    } catch (error) {
      next(error);
    }
  }

  static async completeConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { notes, prescription, followUpDate } = req.body;

      // Only nutritionist can complete consultation
      const consultation = await ConsultationService.completeConsultation(id, {
        nutritionistId: userId,
        notes,
        prescription,
        followUpDate,
      });

      res.json({
        success: true,
        message: 'Consultation completed successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUpcomingReminders(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const reminders = await ConsultationService.getUpcomingReminders(userId);

      res.json({
        success: true,
        data: reminders,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Consultation Service
```typescript
// services/consultation/src/services/consultation.service.ts
import { prisma } from '@nutrition/database';
import { VideoService } from './video.service';
import { NotificationService } from './notification.service';
import { CalendarService } from './calendar.service';
import { PaymentService } from './payment.service';
import { addMinutes, subHours, isAfter, isBefore } from 'date-fns';

interface BookConsultationDto {
  userId: string;
  nutritionistId: string;
  programId?: string;
  scheduledAt: Date;
  duration: number;
  notes?: string;
  timezone: string;
}

export class ConsultationService {
  static async bookConsultation(data: BookConsultationDto) {
    // Start transaction
    return prisma.$transaction(async (tx) => {
      // Check for conflicts
      const conflicts = await tx.consultation.findMany({
        where: {
          OR: [
            { userId: data.userId },
            { nutritionistId: data.nutritionistId },
          ],
          scheduledAt: {
            gte: data.scheduledAt,
            lt: addMinutes(data.scheduledAt, data.duration),
          },
          status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
        },
      });

      if (conflicts.length > 0) {
        throw new Error('Time slot conflict detected');
      }

      // Get nutritionist details for pricing
      const nutritionist = await tx.nutritionistProfile.findUnique({
        where: { userId: data.nutritionistId },
      });

      if (!nutritionist) {
        throw new Error('Nutritionist not found');
      }

      // Create consultation
      const consultation = await tx.consultation.create({
        data: {
          userId: data.userId,
          nutritionistId: data.nutritionistId,
          programId: data.programId,
          scheduledAt: data.scheduledAt,
          duration: data.duration,
          status: 'SCHEDULED',
          notes: data.notes,
        },
        include: {
          user: {
            include: { profile: true },
          },
          nutritionist: {
            include: { profile: true },
          },
        },
      });

      // Create video meeting
      const meeting = await VideoService.createMeeting({
        consultationId: consultation.id,
        topic: `Consultation with ${consultation.nutritionist.profile?.firstName}`,
        startTime: data.scheduledAt,
        duration: data.duration,
        timezone: data.timezone,
      });

      // Update consultation with meeting details
      await tx.consultation.update({
        where: { id: consultation.id },
        data: {
          meetingLink: meeting.joinUrl,
          meetingId: meeting.id,
        },
      });

      // Create calendar events
      await CalendarService.createEvents({
        consultation,
        userTimezone: data.timezone,
      });

      // Schedule reminders
      await this.scheduleReminders(consultation.id, data.scheduledAt);

      // Send confirmation emails
      await NotificationService.sendConsultationBooked(consultation);

      return consultation;
    });
  }

  static async getUserConsultations(userId: string, options: {
    status?: string;
    page: number;
    limit: number;
  }) {
    const where: any = { userId };

    if (options.status) {
      where.status = options.status;
    }

    const [consultations, total] = await Promise.all([
      prisma.consultation.findMany({
        where,
        orderBy: { scheduledAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          nutritionist: {
            include: {
              user: true,
              profile: true,
            },
          },
          program: true,
          payment: true,
        },
      }),
      prisma.consultation.count({ where }),
    ]);

    return {
      consultations,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getConsultation(consultationId: string, userId: string) {
    return prisma.consultation.findFirst({
      where: {
        id: consultationId,
        OR: [
          { userId },
          { nutritionistId: userId },
        ],
      },
      include: {
        user: {
          include: { profile: true },
        },
        nutritionist: {
          include: {
            user: true,
            profile: true,
          },
        },
        program: true,
        payment: true,
        reminders: true,
      },
    });
  }

  static async rescheduleConsultation(
    consultationId: string,
    userId: string,
    newScheduledAt: Date,
    reason: string
  ) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (consultation.status !== 'SCHEDULED') {
      throw new Error('Only scheduled consultations can be rescheduled');
    }

    // Check if within reschedule window (24 hours before)
    const rescheduleDeadline = subHours(consultation.scheduledAt, 24);
    if (isAfter(new Date(), rescheduleDeadline)) {
      throw new Error('Cannot reschedule within 24 hours of appointment');
    }

    // Check new slot availability
    const isAvailable = await CalendarService.checkSlotAvailability(
      consultation.nutritionistId,
      newScheduledAt,
      consultation.duration
    );

    if (!isAvailable) {
      throw new Error('New time slot is not available');
    }

    // Update consultation
    const updated = await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        scheduledAt: newScheduledAt,
        updatedAt: new Date(),
      },
    });

    // Update video meeting
    if (consultation.meetingId) {
      await VideoService.updateMeeting(consultation.meetingId, {
        startTime: newScheduledAt,
      });
    }

    // Cancel old reminders and schedule new ones
    await this.cancelReminders(consultationId);
    await this.scheduleReminders(consultationId, newScheduledAt);

    // Update calendar events
    await CalendarService.updateEvents({
      consultation: updated,
      oldScheduledAt: consultation.scheduledAt,
    });

    // Send notifications
    await NotificationService.sendConsultationRescheduled(updated, reason);

    return updated;
  }

  static async cancelConsultation(
    consultationId: string,
    userId: string,
    reason: string
  ) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (!['SCHEDULED', 'IN_PROGRESS'].includes(consultation.status)) {
      throw new Error('Cannot cancel this consultation');
    }

    // Check cancellation policy
    const cancellationDeadline = subHours(consultation.scheduledAt, 4);
    const isLateCancellation = isAfter(new Date(), cancellationDeadline);

    // Update consultation
    await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        status: 'CANCELLED',
        cancelledAt: new Date(),
        cancellationReason: reason,
      },
    });

    // Cancel video meeting
    if (consultation.meetingId) {
      await VideoService.cancelMeeting(consultation.meetingId);
    }

    // Cancel reminders
    await this.cancelReminders(consultationId);

    // Process refund if applicable
    if (consultation.payment && !isLateCancellation) {
      await PaymentService.processRefund(consultation.payment.id, 'full');
    }

    // Send notifications
    await NotificationService.sendConsultationCancelled(consultation, reason);
  }

  static async getMeetingInfo(consultationId: string, userId: string) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    // Check if it's time to join (15 minutes before to 30 minutes after)
    const now = new Date();
    const joinWindowStart = subHours(consultation.scheduledAt, 0.25); // 15 minutes before
    const joinWindowEnd = addMinutes(consultation.scheduledAt, 30);

    if (isBefore(now, joinWindowStart) || isAfter(now, joinWindowEnd)) {
      throw new Error('Meeting room is not available at this time');
    }

    // Update status if needed
    if (consultation.status === 'SCHEDULED' && isAfter(now, consultation.scheduledAt)) {
      await prisma.consultation.update({
        where: { id: consultationId },
        data: { status: 'IN_PROGRESS' },
      });
    }

    return {
      meetingLink: consultation.meetingLink,
      meetingId: consultation.meetingId,
      hostLink: userId === consultation.nutritionistId 
        ? await VideoService.getHostLink(consultation.meetingId!) 
        : null,
    };
  }

  static async completeConsultation(consultationId: string, data: {
    nutritionistId: string;
    notes?: string;
    prescription?: any;
    followUpDate?: Date;
  }) {
    const consultation = await prisma.consultation.findFirst({
      where: {
        id: consultationId,
        nutritionistId: data.nutritionistId,
      },
    });

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (consultation.status !== 'IN_PROGRESS') {
      throw new Error('Consultation must be in progress to complete');
    }

    // Update consultation
    const updated = await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        status: 'COMPLETED',
        completedAt: new Date(),
        internalNotes: data.notes,
        prescription: data.prescription,
        followUpDate: data.followUpDate,
      },
      include: {
        user: {
          include: { profile: true },
        },
      },
    });

    // Generate prescription PDF if provided
    if (data.prescription) {
      const prescriptionUrl = await this.generatePrescriptionPDF(
        updated,
        data.prescription
      );

      await prisma.consultation.update({
        where: { id: consultationId },
        data: { prescriptionUrl },
      });
    }

    // Send follow-up email with notes
    await NotificationService.sendConsultationCompleted(updated);

    // Schedule follow-up reminder if date provided
    if (data.followUpDate) {
      await this.scheduleFollowUpReminder(consultationId, data.followUpDate);
    }

    return updated;
  }

  static async getUpcomingReminders(userId: string) {
    const upcoming = await prisma.consultation.findMany({
      where: {
        OR: [
          { userId },
          { nutritionistId: userId },
        ],
        status: 'SCHEDULED',
        scheduledAt: {
          gte: new Date(),
          lte: addMinutes(new Date(), 24 * 60), // Next 24 hours
        },
      },
      orderBy: { scheduledAt: 'asc' },
      include: {
        user: {
          include: { profile: true },
        },
        nutritionist: {
          include: { profile: true },
        },
      },
    });

    return upcoming;
  }

  private static async scheduleReminders(consultationId: string, scheduledAt: Date) {
    const reminderTimes = [
      { type: 'email', minutesBefore: 24 * 60 }, // 1 day before
      { type: 'email', minutesBefore: 60 }, // 1 hour before
      { type: 'sms', minutesBefore: 30 }, // 30 minutes before
      { type: 'whatsapp', minutesBefore: 15 }, // 15 minutes before
    ];

    const reminders = reminderTimes.map((reminder) => ({
      consultationId,
      type: reminder.type,
      scheduledAt: new Date(scheduledAt.getTime() - reminder.minutesBefore * 60 * 1000),
      status: 'pending',
    }));

    await prisma.consultationReminder.createMany({
      data: reminders,
    });
  }

  private static async cancelReminders(consultationId: string) {
    await prisma.consultationReminder.updateMany({
      where: {
        consultationId,
        status: 'pending',
      },
      data: {
        status: 'cancelled',
      },
    });
  }

  private static async scheduleFollowUpReminder(
    consultationId: string,
    followUpDate: Date
  ) {
    await prisma.consultationReminder.create({
      data: {
        consultationId,
        type: 'email',
        scheduledAt: subHours(followUpDate, 24),
        status: 'pending',
      },
    });
  }

  private static async generatePrescriptionPDF(consultation: any, prescription: any) {
    // This would integrate with a PDF generation service
    // For now, returning a placeholder
    return `prescriptions/${consultation.id}.pdf`;
  }
}
```

### Day 5-7: Calendar & Video Integration

#### 1. Calendar Service
```typescript
// services/consultation/src/services/calendar.service.ts
import { google } from 'googleapis';
import { prisma } from '@nutrition/database';
import { addMinutes, format, startOfDay, endOfDay } from 'date-fns';
import { utcToZonedTime, zonedTimeToUtc } from 'date-fns-tz';

export class CalendarService {
  private static oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URL
  );

  static async getAvailableSlots(
    nutritionistId: string,
    date: Date,
    timezone: string
  ) {
    // Get nutritionist availability
    const nutritionist = await prisma.nutritionistProfile.findUnique({
      where: { userId: nutritionistId },
      include: { user: true },
    });

    if (!nutritionist) {
      throw new Error('Nutritionist not found');
    }

    // Get working hours from availability
    const dayOfWeek = format(date, 'EEEE').toLowerCase();
    const workingHours = nutritionist.availability?.[dayOfWeek] || {
      start: '09:00',
      end: '17:00',
      breaks: [{ start: '13:00', end: '14:00' }],
    };

    // Get existing consultations for the day
    const dayStart = startOfDay(date);
    const dayEnd = endOfDay(date);

    const existingConsultations = await prisma.consultation.findMany({
      where: {
        nutritionistId,
        scheduledAt: {
          gte: dayStart,
          lte: dayEnd,
        },
        status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
      },
      select: {
        scheduledAt: true,
        duration: true,
      },
    });

    // Generate available slots
    const slots = this.generateTimeSlots(
      workingHours,
      existingConsultations,
      date,
      timezone
    );

    return slots;
  }

  static async checkSlotAvailability(
    nutritionistId: string,
    scheduledAt: Date,
    duration: number
  ): Promise<boolean> {
    const endTime = addMinutes(scheduledAt, duration);

    const conflicts = await prisma.consultation.count({
      where: {
        nutritionistId,
        status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
        OR: [
          {
            // New consultation starts during existing one
            scheduledAt: {
              lte: scheduledAt,
            },
            AND: {
              scheduledAt: {
                gt: new Date(scheduledAt.getTime() - duration * 60 * 1000),
              },
            },
          },
          {
            // New consultation ends during existing one
            scheduledAt: {
              lt: endTime,
              gte: scheduledAt,
            },
          },
        ],
      },
    });

    return conflicts === 0;
  }

  static async createEvents(data: {
    consultation: any;
    userTimezone: string;
  }) {
    const { consultation, userTimezone } = data;

    // Create calendar event for user
    if (consultation.user.googleCalendarConnected) {
      await this.createGoogleCalendarEvent({
        userId: consultation.userId,
        title: `Nutrition Consultation with ${consultation.nutritionist.profile?.firstName}`,
        description: `Meeting link: ${consultation.meetingLink}\n\nNotes: ${consultation.notes || 'N/A'}`,
        startTime: consultation.scheduledAt,
        endTime: addMinutes(consultation.scheduledAt, consultation.duration),
        timezone: userTimezone,
      });
    }

    // Create calendar event for nutritionist
    if (consultation.nutritionist.user.googleCalendarConnected) {
      await this.createGoogleCalendarEvent({
        userId: consultation.nutritionistId,
        title: `Consultation with ${consultation.user.profile?.firstName} ${consultation.user.profile?.lastName}`,
        description: `Meeting link: ${consultation.meetingLink}\n\nNotes: ${consultation.notes || 'N/A'}`,
        startTime: consultation.scheduledAt,
        endTime: addMinutes(consultation.scheduledAt, consultation.duration),
        timezone: 'Asia/Kolkata', // Nutritionist timezone
      });
    }
  }

  static async updateEvents(data: {
    consultation: any;
    oldScheduledAt: Date;
  }) {
    // This would update existing calendar events
    // Implementation depends on storing event IDs
  }

  private static generateTimeSlots(
    workingHours: any,
    existingConsultations: any[],
    date: Date,
    timezone: string
  ) {
    const slots: Array<{ time: Date; available: boolean }> = [];
    const slotDuration = 30; // 30-minute slots

    // Parse working hours
    const [startHour, startMinute] = workingHours.start.split(':').map(Number);
    const [endHour, endMinute] = workingHours.end.split(':').map(Number);

    let currentSlot = new Date(date);
    currentSlot.setHours(startHour, startMinute, 0, 0);

    const endTime = new Date(date);
    endTime.setHours(endHour, endMinute, 0, 0);

    while (currentSlot < endTime) {
      // Check if slot is during break time
      const isBreakTime = workingHours.breaks?.some((breakTime: any) => {
        const [breakStartHour, breakStartMinute] = breakTime.start.split(':').map(Number);
        const [breakEndHour, breakEndMinute] = breakTime.end.split(':').map(Number);

        const breakStart = new Date(date);
        breakStart.setHours(breakStartHour, breakStartMinute, 0, 0);

        const breakEnd = new Date(date);
        breakEnd.setHours(breakEndHour, breakEndMinute, 0, 0);

        return currentSlot >= breakStart && currentSlot < breakEnd;
      });

      // Check if slot conflicts with existing consultations
      const hasConflict = existingConsultations.some((consultation) => {
        const consultEnd = addMinutes(consultation.scheduledAt, consultation.duration);
        return currentSlot >= consultation.scheduledAt && currentSlot < consultEnd;
      });

      // Check if slot is in the past
      const isPast = currentSlot < new Date();

      slots.push({
        time: zonedTimeToUtc(currentSlot, timezone),
        available: !isBreakTime && !hasConflict && !isPast,
      });

      currentSlot = addMinutes(currentSlot, slotDuration);
    }

    return slots;
  }

  private static async createGoogleCalendarEvent(data: {
    userId: string;
    title: string;
    description: string;
    startTime: Date;
    endTime: Date;
    timezone: string;
  }) {
    try {
      // Get user's Google tokens
      const tokens = await this.getUserGoogleTokens(data.userId);
      if (!tokens) return;

      this.oauth2Client.setCredentials(tokens);
      const calendar = google.calendar({ version: 'v3', auth: this.oauth2Client });

      const event = {
        summary: data.title,
        description: data.description,
        start: {
          dateTime: data.startTime.toISOString(),
          timeZone: data.timezone,
        },
        end: {
          dateTime: data.endTime.toISOString(),
          timeZone: data.timezone,
        },
        reminders: {
          useDefault: false,
          overrides: [
            { method: 'email', minutes: 60 },
            { method: 'popup', minutes: 15 },
          ],
        },
      };

      await calendar.events.insert({
        calendarId: 'primary',
        requestBody: event,
      });
    } catch (error) {
      console.error('Failed to create Google Calendar event:', error);
    }
  }

  private static async getUserGoogleTokens(userId: string) {
    // This would fetch stored Google OAuth tokens from database
    // Implementation depends on OAuth flow implementation
    return null;
  }
}
```

#### 2. Video Service
```typescript
// services/consultation/src/services/video.service.ts
import axios from 'axios';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

interface CreateMeetingDto {
  consultationId: string;
  topic: string;
  startTime: Date;
  duration: number;
  timezone: string;
}

export class VideoService {
  private static readonly ZOOM_API_URL = 'https://api.zoom.us/v2';
  private static readonly JWT_SECRET = process.env.ZOOM_JWT_SECRET!;
  private static readonly JWT_KEY = process.env.ZOOM_JWT_KEY!;

  static async createMeeting(data: CreateMeetingDto) {
    const token = this.generateZoomJWT();

    try {
      const response = await axios.post(
        `${this.ZOOM_API_URL}/users/me/meetings`,
        {
          topic: data.topic,
          type: 2, // Scheduled meeting
          start_time: data.startTime.toISOString(),
          duration: data.duration,
          timezone: data.timezone,
          password: this.generateMeetingPassword(),
          settings: {
            host_video: true,
            participant_video: true,
            join_before_host: false,
            mute_upon_entry: true,
            watermark: false,
            use_pmi: false,
            approval_type: 0,
            audio: 'both',
            auto_recording: 'cloud',
            waiting_room: true,
          },
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return {
        id: response.data.id.toString(),
        joinUrl: response.data.join_url,
        startUrl: response.data.start_url,
        password: response.data.password,
      };
    } catch (error) {
      console.error('Failed to create Zoom meeting:', error);
      // Fallback to Jitsi Meet
      return this.createJitsiMeeting(data);
    }
  }

  static async updateMeeting(meetingId: string, updates: {
    startTime?: Date;
    duration?: number;
  }) {
    const token = this.generateZoomJWT();

    try {
      await axios.patch(
        `${this.ZOOM_API_URL}/meetings/${meetingId}`,
        {
          start_time: updates.startTime?.toISOString(),
          duration: updates.duration,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );
    } catch (error) {
      console.error('Failed to update Zoom meeting:', error);
    }
  }

  static async cancelMeeting(meetingId: string) {
    const token = this.generateZoomJWT();

    try {
      await axios.delete(
        `${this.ZOOM_API_URL}/meetings/${meetingId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
    } catch (error) {
      console.error('Failed to cancel Zoom meeting:', error);
    }
  }

  static async getHostLink(meetingId: string): Promise<string> {
    // For Zoom, the host link is stored separately
    // For Jitsi, we can generate it with moderator params
    if (meetingId.startsWith('jitsi_')) {
      const roomName = meetingId.replace('jitsi_', '');
      return `https://meet.jit.si/${roomName}#config.prejoinPageEnabled=false&userInfo.displayName=Nutritionist`;
    }

    // For Zoom, return the stored start URL
    return '';
  }

  private static createJitsiMeeting(data: CreateMeetingDto) {
    // Jitsi Meet doesn't require API calls for room creation
    const roomName = `nutrition_${data.consultationId}_${Date.now()}`;
    const joinUrl = `https://meet.jit.si/${roomName}`;

    return {
      id: `jitsi_${roomName}`,
      joinUrl,
      startUrl: joinUrl,
      password: '',
    };
  }

  private static generateZoomJWT(): string {
    const payload = {
      iss: this.JWT_KEY,
      exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour expiry
    };

    return jwt.sign(payload, this.JWT_SECRET);
  }

  private static generateMeetingPassword(): string {
    return crypto.randomBytes(4).toString('hex').substring(0, 6);
  }
}
```

## Week 5: Payment Integration & Security

### Day 1-3: Payment Service Implementation

#### 1. Payment Controller
```typescript
// services/payment/src/controllers/payment.controller.ts
import { Request, Response, NextFunction } from 'express';
import { PaymentService } from '../services/payment.service';
import { InvoiceService } from '../services/invoice.service';
import { AppError } from '../utils/errors';

export class PaymentController {
  static async createOrder(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { 
        amount, 
        currency = 'INR', 
        type, 
        referenceId,
        gateway = 'razorpay' 
      } = req.body;

      const order = await PaymentService.createOrder({
        userId,
        amount,
        currency,
        type,
        referenceId,
        gateway,
      });

      res.json({
        success: true,
        data: order,
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyPayment(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { 
        orderId, 
        paymentId, 
        signature,
        gateway = 'razorpay' 
      } = req.body;

      const payment = await PaymentService.verifyPayment({
        userId,
        orderId,
        paymentId,
        signature,
        gateway,
      });

      res.json({
        success: true,
        message: 'Payment verified successfully',
        data: payment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async handleWebhook(req: Request, res: Response, next: NextFunction) {
    try {
      const signature = req.headers['x-razorpay-signature'] as string;
      const gateway = req.params.gateway;

      await PaymentService.handleWebhook({
        gateway,
        signature,
        payload: req.body,
      });

      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  }

  static async getPaymentHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { status, page = 1, limit = 10 } = req.query;

      const payments = await PaymentService.getPaymentHistory(userId, {
        status: status as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: payments,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getInvoice(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;

      const invoice = await InvoiceService.getInvoice(paymentId, userId);

      res.json({
        success: true,
        data: invoice,
      });
    } catch (error) {
      next(error);
    }
  }

  static async downloadInvoice(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;

      const invoiceBuffer = await InvoiceService.generateInvoicePDF(
        paymentId,
        userId
      );

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="invoice-${paymentId}.pdf"`
      );
      res.send(invoiceBuffer);
    } catch (error) {
      next(error);
    }
  }

  static async initiateRefund(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;
      const { amount, reason } = req.body;

      const refund = await PaymentService.initiateRefund({
        paymentId,
        userId,
        amount,
        reason,
      });

      res.json({
        success: true,
        message: 'Refund initiated successfully',
        data: refund,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPaymentMethods(req: Request, res: Response, next: NextFunction) {
    try {
      const methods = await PaymentService.getAvailablePaymentMethods();

      res.json({
        success: true,
        data: methods,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Payment Service with Razorpay Integration
```typescript
// services/payment/src/services/payment.service.ts
import Razorpay from 'razorpay';
import crypto from 'crypto';
import { prisma } from '@nutrition/database';
import { PaymentGateway } from './gateways/payment.gateway';
import { RazorpayGateway } from './gateways/razorpay.gateway';
import { CashfreeGateway } from './gateways/cashfree.gateway';
import { generateInvoiceNumber } from '../utils/invoice.utils';

interface CreateOrderDto {
  userId: string;
  amount: number;
  currency: string;
  type: string;
  referenceId: string;
  gateway: string;
}

interface VerifyPaymentDto {
  userId: string;
  orderId: string;
  paymentId: string;
  signature: string;
  gateway: string;
}

export class PaymentService {
  private static gateways: Record<string, PaymentGateway> = {
    razorpay: new RazorpayGateway(),
    cashfree: new CashfreeGateway(),
  };

  static async createOrder(data: CreateOrderDto) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Create order in gateway
    const gatewayOrder = await gateway.createOrder({
      amount: data.amount,
      currency: data.currency,
      receipt: `order_${Date.now()}`,
      notes: {
        userId: data.userId,
        type: data.type,
        referenceId: data.referenceId,
      },
    });

    // Create payment record
    const payment = await prisma.payment.create({
      data: {
        userId: data.userId,
        amount: data.amount,
        currency: data.currency,
        status: 'PENDING',
        gateway: data.gateway,
        gatewayOrderId: gatewayOrder.id,
        metadata: {
          type: data.type,
          referenceId: data.referenceId,
        },
      },
    });

    return {
      paymentId: payment.id,
      orderId: gatewayOrder.id,
      amount: data.amount,
      currency: data.currency,
      gateway: data.gateway,
      gatewayData: gatewayOrder,
    };
  }

  static async verifyPayment(data: VerifyPaymentDto) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Get payment record
    const payment = await prisma.payment.findFirst({
      where: {
        userId: data.userId,
        gatewayOrderId: data.orderId,
        status: 'PENDING',
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    // Verify signature
    const isValid = await gateway.verifySignature({
      orderId: data.orderId,
      paymentId: data.paymentId,
      signature: data.signature,
    });

    if (!isValid) {
      throw new Error('Invalid payment signature');
    }

    // Update payment status
    const updatedPayment = await prisma.payment.update({
      where: { id: payment.id },
      data: {
        status: 'SUCCESS',
        gatewayPaymentId: data.paymentId,
        gatewaySignature: data.signature,
        invoiceNumber: generateInvoiceNumber(),
        updatedAt: new Date(),
      },
    });

    // Handle post-payment actions based on type
    await this.handlePostPaymentActions(updatedPayment);

    return updatedPayment;
  }

  static async handleWebhook(data: {
    gateway: string;
    signature: string;
    payload: any;
  }) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Verify webhook signature
    const isValid = await gateway.verifyWebhookSignature(
      data.payload,
      data.signature
    );

    if (!isValid) {
      throw new Error('Invalid webhook signature');
    }

    // Process webhook based on event type
    const event = gateway.parseWebhookEvent(data.payload);

    switch (event.type) {
      case 'payment.captured':
        await this.handlePaymentCaptured(event.data);
        break;
      case 'payment.failed':
        await this.handlePaymentFailed(event.data);
        break;
      case 'refund.processed':
        await this.handleRefundProcessed(event.data);
        break;
      default:
        console.log('Unhandled webhook event:', event.type);
    }
  }

  static async getPaymentHistory(userId: string, options: {
    status?: string;
    page: number;
    limit: number;
  }) {
    const where: any = { userId };

    if (options.status) {
      where.status = options.status;
    }

    const [payments, total] = await Promise.all([
      prisma.payment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          consultation: {
            include: {
              nutritionist: {
                include: { profile: true },
              },
            },
          },
          journey: {
            include: { program: true },
          },
        },
      }),
      prisma.payment.count({ where }),
    ]);

    return {
      payments,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async initiateRefund(data: {
    paymentId: string;
    userId: string;
    amount?: number;
    reason: string;
  }) {
    const payment = await prisma.payment.findFirst({
      where: {
        id: data.paymentId,
        userId: data.userId,
        status: 'SUCCESS',
      },
    });

    if (!payment) {
      throw new Error('Payment not found or not eligible for refund');
    }

    // Check if already refunded
    if (payment.refundId) {
      throw new Error('Payment already refunded');
    }

    const gateway = this.gateways[payment.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Initiate refund with gateway
    const refundAmount = data.amount || payment.amount;
    const refund = await gateway.initiateRefund({
      paymentId: payment.gatewayPaymentId!,
      amount: refundAmount,
      notes: {
        reason: data.reason,
      },
    });

    // Update payment record
    await prisma.payment.update({
      where: { id: payment.id },
      data: {
        refundId: refund.id,
        refundAmount: refundAmount,
        refundedAt: new Date(),
        status: refundAmount === payment.amount ? 'REFUNDED' : 'PARTIALLY_REFUNDED',
      },
    });

    return refund;
  }

  static async getAvailablePaymentMethods() {
    return [
      {
        id: 'upi',
        name: 'UPI',
        description: 'Pay using any UPI app',
        icon: 'upi-icon',
        enabled: true,
      },
      {
        id: 'card',
        name: 'Credit/Debit Card',
        description: 'All major cards accepted',
        icon: 'card-icon',
        enabled: true,
      },
      {
        id: 'netbanking',
        name: 'Net Banking',
        description: 'All major banks supported',
        icon: 'bank-icon',
        enabled: true,
      },
      {
        id: 'wallet',
        name: 'Wallet',
        description: 'Paytm, PhonePe, etc.',
        icon: 'wallet-icon',
        enabled: true,
      },
    ];
  }

  private static async handlePostPaymentActions(payment: any) {
    const metadata = payment.metadata as any;

    switch (metadata.type) {
      case 'consultation':
        await this.activateConsultation(metadata.referenceId);
        break;
      case 'program':
        await this.activateProgramEnrollment(payment.userId, metadata.referenceId);
        break;
      case 'subscription':
        await this.activateSubscription(payment.userId, metadata.referenceId);
        break;
    }

    // Send payment confirmation
    await this.sendPaymentConfirmation(payment);
  }

  private static async handlePaymentCaptured(data: any) {
    await prisma.payment.update({
      where: { gatewayPaymentId: data.id },
      data: {
        status: 'SUCCESS',
        paymentMethod: data.method,
      },
    });
  }

  private static async handlePaymentFailed(data: any) {
    await prisma.payment.update({
      where: { gatewayPaymentId: data.id },
      data: {
        status: 'FAILED',
        failureReason: data.error?.description,
      },
    });
  }

  private static async handleRefundProcessed(data: any) {
    await prisma.payment.update({
      where: { refundId: data.id },
      data: {
        status: data.amount === data.payment_amount ? 'REFUNDED' : 'PARTIALLY_REFUNDED',
      },
    });
  }

  private static async activateConsultation(consultationId: string) {
    // Implementation for activating consultation after payment
  }

  private static async activateProgramEnrollment(userId: string, programId: string) {
    // Implementation for activating program enrollment
  }

  private static async activateSubscription(userId: string, planId: string) {
    // Implementation for activating subscription
  }

  private static async sendPaymentConfirmation(payment: any) {
    // Send email confirmation
  }
}
```

#### 3. Razorpay Gateway Implementation
```typescript
// services/payment/src/services/gateways/razorpay.gateway.ts
import Razorpay from 'razorpay';
import crypto from 'crypto';
import { PaymentGateway } from './payment.gateway';

export class RazorpayGateway implements PaymentGateway {
  private razorpay: Razorpay;

  constructor() {
    this.razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID!,
      key_secret: process.env.RAZORPAY_KEY_SECRET!,
    });
  }

  async createOrder(data: {
    amount: number;
    currency: string;
    receipt: string;
    notes?: any;
  }) {
    const order = await this.razorpay.orders.create({
      amount: Math.round(data.amount * 100), // Convert to paise
      currency: data.currency,
      receipt: data.receipt,
      notes: data.notes,
    });

    return {
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      status: order.status,
    };
  }

  async verifySignature(data: {
    orderId: string;
    paymentId: string;
    signature: string;
  }): Promise<boolean> {
    const text = `${data.orderId}|${data.paymentId}`;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET!)
      .update(text)
      .digest('hex');

    return expectedSignature === data.signature;
  }

  async verifyWebhookSignature(payload: any, signature: string): Promise<boolean> {
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET!)
      .update(JSON.stringify(payload))
      .digest('hex');

    return expectedSignature === signature;
  }

  parseWebhookEvent(payload: any) {
    return {
      type: payload.event,
      data: payload.payload.payment?.entity || payload.payload.refund?.entity,
    };
  }

  async initiateRefund(data: {
    paymentId: string;
    amount: number;
    notes?: any;
  }) {
    const refund = await this.razorpay.payments.refund(data.paymentId, {
      amount: Math.round(data.amount * 100),
      notes: data.notes,
    });

    return {
      id: refund.id,
      amount: refund.amount,
      status: refund.status,
    };
  }

  async fetchPayment(paymentId: string) {
    return this.razorpay.payments.fetch(paymentId);
  }
}
```

### Day 4-5: Invoice Generation

#### 1. Invoice Service
```typescript
// services/payment/src/services/invoice.service.ts
import PDFDocument from 'pdfkit';
import { prisma } from '@nutrition/database';
import { uploadToStorage } from '../utils/storage';
import { formatCurrency, formatDate } from '../utils/format.utils';

export class InvoiceService {
  static async generateInvoice(paymentId: string) {
    const payment = await prisma.payment.findUnique({
      where: { id: paymentId },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    // Generate PDF
    const pdfBuffer = await this.createInvoicePDF(payment);

    // Upload to storage
    const filename = `invoices/${payment.invoiceNumber}.pdf`;
    const invoiceUrl = await uploadToStorage(pdfBuffer, filename, 'application/pdf');

    // Update payment with invoice URL
    await prisma.payment.update({
      where: { id: paymentId },
      data: { invoiceUrl },
    });

    return invoiceUrl;
  }

  static async getInvoice(paymentId: string, userId: string) {
    const payment = await prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId,
        status: 'SUCCESS',
      },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Invoice not found');
    }

    return {
      invoiceNumber: payment.invoiceNumber,
      invoiceUrl: payment.invoiceUrl,
      payment,
    };
  }

  static async generateInvoicePDF(paymentId: string, userId: string): Promise<Buffer> {
    const payment = await prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId,
        status: 'SUCCESS',
      },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    return this.createInvoicePDF(payment);
  }

  private static async createInvoicePDF(payment: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 50 });
      const buffers: Buffer[] = [];

      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', reject);

      // Header
      doc
        .fontSize(24)
        .text('INVOICE', 50, 50)
        .fontSize(10)
        .text(`Invoice Number: ${payment.invoiceNumber}`, 50, 80)
        .text(`Date: ${formatDate(payment.createdAt)}`, 50, 95);

      // Company Details
      doc
        .fontSize(16)
        .text('Nutrition Platform', 300, 50)
        .fontSize(10)
        .text('123 Health Street', 300, 75)
        .text('Mumbai, MH 400001', 300, 90)
        .text('GSTIN: 27AAAAA0000A1Z5', 300, 105);

      // Bill To
      doc
        .fontSize(12)
        .text('Bill To:', 50, 150)
        .fontSize(10)
        .text(
          `${payment.user.profile?.firstName} ${payment.user.profile?.lastName}`,
          50,
          170
        )
        .text(payment.user.email, 50, 185)
        .text(payment.user.phone || '', 50, 200);

      // Line Items
      doc.moveTo(50, 250).lineTo(550, 250).stroke();

      doc
        .fontSize(12)
        .text('Description', 50, 260)
        .text('Amount', 450, 260, { align: 'right' });

      doc.moveTo(50, 280).lineTo(550, 280).stroke();

      // Item details
      let description = '';
      if (payment.consultation) {
        description = `Consultation with ${payment.consultation.nutritionist.profile?.firstName} ${payment.consultation.nutritionist.profile?.lastName}`;
      } else if (payment.journey) {
        description = `${payment.journey.program.name} Program`;
      }

      doc
        .fontSize(10)
        .text(description, 50, 290)
        .text(formatCurrency(payment.amount, payment.currency), 450, 290, {
          align: 'right',
        });

      // GST Calculation
      const gstRate = 0.18; // 18% GST
      const baseAmount = payment.amount / (1 + gstRate);
      const gstAmount = payment.amount - baseAmount;

      doc
        .text('Subtotal', 350, 330)
        .text(formatCurrency(baseAmount, payment.currency), 450, 330, {
          align: 'right',
        })
        .text('GST (18%)', 350, 350)
        .text(formatCurrency(gstAmount, payment.currency), 450, 350, {
          align: 'right',
        });

      doc.moveTo(350, 370).lineTo(550, 370).stroke();

      doc
        .fontSize(12)
        .text('Total', 350, 380)
        .text(formatCurrency(payment.amount, payment.currency), 450, 380, {
          align: 'right',
        });

      // Payment Details
      doc
        .fontSize(10)
        .text('Payment Details:', 50, 450)
        .text(`Payment ID: ${payment.gatewayPaymentId}`, 50, 470)
        .text(`Payment Method: ${payment.paymentMethod || 'Online'}`, 50, 485)
        .text(`Status: ${payment.status}`, 50, 500);

      // Footer
      doc
        .fontSize(8)
        .text(
          'This is a computer-generated invoice and does not require a signature.',
          50,
          700,
          { align: 'center' }
        );

      doc.end();
    });
  }
}
```

### Day 6-7: Security Implementation

#### 1. Security Middleware
```typescript
// packages/security/src/middleware/security.middleware.ts
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://www.google-analytics.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.razorpay.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'self'", 'https://api.razorpay.com'],
    },
  },
  crossOriginEmbedderPolicy: false,
});

export const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true,
});

export const uploadRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Upload limit exceeded, please try again later.',
});

export const sanitizeInput = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized ${key} in request from ${req.ip}`);
  },
});

export const preventParamPollution = hpp({
  whitelist: ['sort', 'fields', 'page', 'limit'],
});

export const generateCSRFToken = (req: Request, res: Response, next: NextFunction) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
};

export const validateCSRFToken = (req: Request, res: Response, next: NextFunction) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const token = req.body._csrf || req.headers['x-csrf-token'];
  
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({
      success: false,
      error: 'Invalid CSRF token',
    });
  }

  next();
};

export const validateInput = (schema: any) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map((detail: any) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return res.status(400).json({
        success: false,
        errors,
      });
    }

    next();
  };
};

export const encryptSensitiveData = (data: any, fields: string[]) => {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  
  const encrypted = { ...data };

  fields.forEach((field) => {
    if (data[field]) {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      
      let encryptedData = cipher.update(data[field], 'utf8', 'hex');
      encryptedData += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      encrypted[field] = {
        data: encryptedData,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
      };
    }
  });

  return encrypted;
};

export const decryptSensitiveData = (data: any, fields: string[]) => {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  
  const decrypted = { ...data };

  fields.forEach((field) => {
    if (data[field] && typeof data[field] === 'object') {
      const { data: encryptedData, iv, authTag } = data[field];
      
      const decipher = crypto.createDecipheriv(
        algorithm,
        key,
        Buffer.from(iv, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
      decryptedData += decipher.final('utf8');
      
      decrypted[field] = decryptedData;
    }
  });

  return decrypted;
};
```

#### 2. API Security Service
```typescript
// packages/security/src/services/api-security.service.ts
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { prisma } from '@nutrition/database';

export class APISecurityService {
  private static readonly API_KEY_PREFIX = 'ntp_';
  private static readonly WEBHOOK_TOLERANCE = 300; // 5 minutes

  static async generateAPIKey(userId: string, name: string): Promise<string> {
    const key = `${this.API_KEY_PREFIX}${crypto.randomBytes(32).toString('hex')}`;
    const hashedKey = this.hashAPIKey(key);

    await prisma.apiKey.create({
      data: {
        userId,
        name,
        key: hashedKey,
        lastUsedAt: null,
      },
    });

    return key;
  }

  static async validateAPIKey(key: string): Promise<boolean> {
    if (!key.startsWith(this.API_KEY_PREFIX)) {
      return false;
    }

    const hashedKey = this.hashAPIKey(key);
    
    const apiKey = await prisma.apiKey.findUnique({
      where: { key: hashedKey },
      include: { user: true },
    });

    if (!apiKey || !apiKey.isActive) {
      return false;
    }

    // Update last used
    await prisma.apiKey.update({
      where: { id: apiKey.id },
      data: { lastUsedAt: new Date() },
    });

    return true;
  }

  static validateWebhookSignature(
    payload: string,
    signature: string,
    secret: string,
    timestamp?: number
  ): boolean {
    // Check timestamp to prevent replay attacks
    if (timestamp) {
      const currentTime = Math.floor(Date.now() / 1000);
      if (Math.abs(currentTime - timestamp) > this.WEBHOOK_TOLERANCE) {
        return false;
      }
    }

    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(timestamp ? `${timestamp}.${payload}` : payload)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  static generateRequestSignature(
    method: string,
    path: string,
    body: any,
    timestamp: number,
    secret: string
  ): string {
    const payload = `${method.toUpperCase()}${path}${JSON.stringify(body)}${timestamp}`;
    
    return crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');
  }

  static validateRequestSignature(req: Request, secret: string): boolean {
    const signature = req.headers['x-signature'] as string;
    const timestamp = parseInt(req.headers['x-timestamp'] as string);

    if (!signature || !timestamp) {
      return false;
    }

    const expectedSignature = this.generateRequestSignature(
      req.method,
      req.path,
      req.body,
      timestamp,
      secret
    );

    return this.validateWebhookSignature(
      JSON.stringify(req.body),
      signature,
      secret,
      timestamp
    );
  }

  static encryptAPIResponse(data: any, key: string): string {
    const algorithm = 'aes-256-cbc';
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);

    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return iv.toString('hex') + ':' + encrypted;
  }

  static decryptAPIRequest(encryptedData: string, key: string): any {
    const [ivHex, encrypted] = encryptedData.split(':');
    const algorithm = 'aes-256-cbc';
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  }

  private static hashAPIKey(key: string): string {
    return crypto
      .createHash('sha256')
      .update(key)
      .digest('hex');
  }

  static async logAPIAccess(req: Request, apiKeyId: string) {
    await prisma.apiAccessLog.create({
      data: {
        apiKeyId,
        method: req.method,
        path: req.path,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        statusCode: 200, // Will be updated by response interceptor
        responseTime: 0, // Will be updated by response interceptor
      },
    });
  }

  static generateJWT(payload: any, expiresIn: string = '1h'): string {
    return jwt.sign(payload, process.env.JWT_SECRET!, {
      expiresIn,
      algorithm: 'HS256',
    });
  }

  static verifyJWT(token: string): any {
    return jwt.verify(token, process.env.JWT_SECRET!);
  }
}
```

## Week 6: Quiz Engine & Recommendation System

### Day 1-3: Quiz Service Implementation

#### 1. Quiz Controller
```typescript
// services/quiz/src/controllers/quiz.controller.ts
import { Request, Response, NextFunction } from 'express';
import { QuizService } from '../services/quiz.service';
import { RecommendationService } from '../services/recommendation.service';
import { AppError } from '../utils/errors';

export class QuizController {
  static async getQuizByType(req: Request, res: Response, next: NextFunction) {
    try {
      const { type } = req.params;
      const userId = req.user?.userId;

      const quiz = await QuizService.getQuizByType(type);

      if (!quiz) {
        throw new AppError('Quiz not found', 404);
      }

      // Get previous results if user is authenticated
      let previousResult = null;
      if (userId) {
        previousResult = await QuizService.getLatestResult(userId, type);
      }

      res.json({
        success: true,
        data: {
          quiz,
          previousResult,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async submitQuiz(req: Request, res: Response, next: NextFunction) {
    try {
      const { type } = req.params;
      const { responses } = req.body;
      const userId = req.user?.userId;

      // Validate responses
      const validation = await QuizService.validateResponses(type, responses);
      if (!validation.valid) {
        throw new AppError('Invalid responses', 400, validation.errors);
      }

      // Process quiz
      const result = await QuizService.processQuizSubmission({
        quizType: type,
        responses,
        userId,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      // Generate recommendations
      const recommendations = await RecommendationService.generateRecommendations(
        result
      );

      res.json({
        success: true,
        data: {
          result,
          recommendations,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizResults(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { page = 1, limit = 10 } = req.query;

      const results = await QuizService.getUserQuizResults(userId, {
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: results,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizResult(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const result = await QuizService.getQuizResult(id, userId);

      if (!result) {
        throw new AppError('Quiz result not found', 404);
      }

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizAnalytics(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const analytics = await QuizService.getUserQuizAnalytics(userId);

      res.json({
        success: true,
        data: analytics,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Quiz Service
```typescript
// services/quiz/src/services/quiz.service.ts
import { prisma } from '@nutrition/database';
import { QuizEngine } from '../engines/quiz.engine';
import { SymptomQuizEngine } from '../engines/symptom.quiz.engine';
import { GutHealthQuizEngine } from '../engines/gut-health.quiz.engine';
import { StressQuizEngine } from '../engines/stress.quiz.engine';

interface QuizSubmission {
  quizType: string;
  responses: Record<string, any>;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export class QuizService {
  private static engines: Record<string, QuizEngine> = {
    symptom: new SymptomQuizEngine(),
    gut_health: new GutHealthQuizEngine(),
    stress: new StressQuizEngine(),
  };

  static async getQuizByType(type: string) {
    const quiz = await prisma.quiz.findFirst({
      where: {
        type: type.toUpperCase(),
        isActive: true,
      },
    });

    if (!quiz) {
      return null;
    }

    // Parse questions and add frontend-friendly structure
    const questions = quiz.questions as any[];
    const formattedQuestions = questions.map((q, index) => ({
      id: q.id || `q${index + 1}`,
      text: q.text,
      type: q.type || 'single_choice',
      required: q.required !== false,
      options: q.options || [],
      validation: q.validation || {},
      conditionalLogic: q.conditionalLogic || null,
    }));

    return {
      ...quiz,
      questions: formattedQuestions,
      estimatedTime: this.calculateEstimatedTime(formattedQuestions),
    };
  }

  static async validateResponses(
    quizType: string,
    responses: Record<string, any>
  ) {
    const quiz = await this.getQuizByType(quizType);
    if (!quiz) {
      return { valid: false, errors: ['Quiz not found'] };
    }

    const errors: string[] = [];
    const questions = quiz.questions as any[];

    for (const question of questions) {
      const response = responses[question.id];

      // Check required fields
      if (question.required && !response) {
        errors.push(`Question "${question.text}" is required`);
        continue;
      }

      // Validate response type
      if (response) {
        switch (question.type) {
          case 'single_choice':
            if (!question.options.find((opt: any) => opt.value === response)) {
              errors.push(`Invalid response for "${question.text}"`);
            }
            break;
          case 'multiple_choice':
            if (!Array.isArray(response)) {
              errors.push(`"${question.text}" requires multiple selections`);
            }
            break;
          case 'scale':
            const value = Number(response);
            if (isNaN(value) || value < 1 || value > 10) {
              errors.push(`"${question.text}" must be between 1 and 10`);
            }
            break;
          case 'text':
            if (question.validation?.maxLength && response.length > question.validation.maxLength) {
              errors.push(`"${question.text}" exceeds maximum length`);
            }
            break;
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async processQuizSubmission(submission: QuizSubmission) {
    const quiz = await prisma.quiz.findFirst({
      where: {
        type: submission.quizType.toUpperCase(),
        isActive: true,
      },
    });

    if (!quiz) {
      throw new Error('Quiz not found');
    }

    // Get the appropriate engine
    const engine = this.engines[submission.quizType.toLowerCase()];
    if (!engine) {
      throw new Error('Quiz engine not found');
    }

    // Calculate score and analysis
    const { score, analysis, riskFactors } = await engine.processResponses(
      submission.responses,
      quiz.scoring as any
    );

    // Save quiz result
    const result = await prisma.quizResult.create({
      data: {
        userId: submission.userId,
        quizId: quiz.id,
        quizType: quiz.type,
        responses: submission.responses,
        score,
        analysis,
        recommendations: await engine.generateRecommendations(score, analysis),
        ipAddress: submission.ipAddress,
        userAgent: submission.userAgent,
      },
    });

    // If user is authenticated, update their profile with insights
    if (submission.userId) {
      await this.updateUserInsights(submission.userId, quiz.type, analysis);
    }

    return result;
  }

  static async getLatestResult(userId: string, quizType: string) {
    return prisma.quizResult.findFirst({
      where: {
        userId,
        quizType: quizType.toUpperCase(),
      },
      orderBy: { completedAt: 'desc' },
    });
  }

  static async getUserQuizResults(userId: string, options: {
    page: number;
    limit: number;
  }) {
    const [results, total] = await Promise.all([
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          quiz: true,
        },
      }),
      prisma.quizResult.count({ where: { userId } }),
    ]);

    return {
      results,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getQuizResult(resultId: string, userId?: string) {
    const where: any = { id: resultId };
    
    // If userId is provided, ensure the result belongs to them
    if (userId) {
      where.userId = userId;
    }

    return prisma.quizResult.findFirst({
      where,
      include: {
        quiz: true,
      },
    });
  }

  static async getUserQuizAnalytics(userId: string) {
    const results = await prisma.quizResult.findMany({
      where: { userId },
      orderBy: { completedAt: 'asc' },
    });

    const analytics = {
      totalQuizzesTaken: results.length,
      quizzesByType: {} as Record<string, number>,
      progressOverTime: {} as Record<string, any[]>,
      latestInsights: {} as Record<string, any>,
    };

    // Group by quiz type
    results.forEach((result) => {
      const type = result.quizType;
      analytics.quizzesByType[type] = (analytics.quizzesByType[type] || 0) + 1;

      if (!analytics.progressOverTime[type]) {
        analytics.progressOverTime[type] = [];
      }

      analytics.progressOverTime[type].push({
        date: result.completedAt,
        score: result.score,
        insights: result.analysis,
      });

      // Keep latest insights
      if (!analytics.latestInsights[type] || 
          result.completedAt > analytics.latestInsights[type].date) {
        analytics.latestInsights[type] = {
          date: result.completedAt,
          analysis: result.analysis,
          recommendations: result.recommendations,
        };
      }
    });

    return analytics;
  }

  private static calculateEstimatedTime(questions: any[]): number {
    // Estimate based on question types
    let totalSeconds = 0;

    questions.forEach((question) => {
      switch (question.type) {
        case 'single_choice':
          totalSeconds += 10;
          break;
        case 'multiple_choice':
          totalSeconds += 15;
          break;
        case 'scale':
          totalSeconds += 8;
          break;
        case 'text':
          totalSeconds += 30;
          break;
        default:
          totalSeconds += 10;
      }
    });

    return Math.ceil(totalSeconds / 60); // Return in minutes
  }

  private static async updateUserInsights(
    userId: string,
    quizType: string,
    analysis: any
  ) {
    const profile = await prisma.userProfile.findUnique({
      where: { userId },
    });

    if (!profile) {
      return;
    }

    const currentInsights = profile.preferences?.healthInsights || {};
    currentInsights[quizType.toLowerCase()] = {
      ...analysis,
      updatedAt: new Date(),
    };

    await prisma.userProfile.update({
      where: { userId },
      data: {
        preferences: {
          ...profile.preferences,
          healthInsights: currentInsights,
        },
      },
    });
  }
}
```

#### 3. Quiz Engine Implementation
```typescript
// services/quiz/src/engines/symptom.quiz.engine.ts
import { QuizEngine } from './quiz.engine';

export class SymptomQuizEngine implements QuizEngine {
  async processResponses(responses: Record<string, any>, scoring: any) {
    let totalScore = 0;
    const categoryScores: Record<string, number> = {
      digestive: 0,
      energy: 0,
      mental: 0,
      hormonal: 0,
      immune: 0,
    };

    const riskFactors: string[] = [];

    // Process each response
    Object.entries(responses).forEach(([questionId, response]) => {
      const questionScoring = scoring[questionId];
      if (!questionScoring) return;

      // Calculate score based on response
      let questionScore = 0;
      if (typeof response === 'number') {
        questionScore = response;
      } else if (questionScoring.options?.[response]) {
        questionScore = questionScoring.options[response];
      }

      totalScore += questionScore;

      // Add to category scores
      if (questionScoring.category) {
        categoryScores[questionScoring.category] += questionScore;
      }

      // Check for risk factors
      if (questionScore >= 7) {
        riskFactors.push(questionScoring.riskMessage || questionId);
      }
    });

    // Analyze results
    const analysis = this.analyzeResults(totalScore, categoryScores, riskFactors);

    return {
      score: totalScore,
      analysis,
      riskFactors,
    };
  }

  private analyzeResults(
    totalScore: number,
    categoryScores: Record<string, number>,
    riskFactors: string[]
  ) {
    const maxPossibleScore = 100; // Adjust based on actual quiz
    const percentage = (totalScore / maxPossibleScore) * 100;

    let severity = 'low';
    let primaryConcern = '';
    let secondaryConcerns: string[] = [];

    // Determine severity
    if (percentage >= 70) {
      severity = 'high';
    } else if (percentage >= 40) {
      severity = 'moderate';
    }

    // Find primary concern
    const sortedCategories = Object.entries(categoryScores)
      .sort(([, a], [, b]) => b - a);

    if (sortedCategories.length > 0) {
      primaryConcern = sortedCategories[0][0];
      secondaryConcerns = sortedCategories
        .slice(1, 3)
        .filter(([, score]) => score > 0)
        .map(([category]) => category);
    }

    return {
      severity,
      percentage,
      primaryConcern,
      secondaryConcerns,
      categoryBreakdown: categoryScores,
      interpretation: this.getInterpretation(severity, primaryConcern),
    };
  }

  private getInterpretation(severity: string, primaryConcern: string): string {
    const interpretations: Record<string, Record<string, string>> = {
      low: {
        digestive: 'Your digestive health appears to be in good shape. Continue with your current healthy habits.',
        energy: 'Your energy levels seem stable. Maintain your current lifestyle practices.',
        mental: 'Your mental wellness indicators are positive. Keep up the good work!',
        hormonal: 'Your hormonal balance appears healthy. Continue monitoring for any changes.',
        immune: 'Your immune system seems to be functioning well. Keep supporting it with good nutrition.',
      },
      moderate: {
        digestive: 'You may be experiencing some digestive issues. Consider dietary adjustments and stress management.',
        energy: 'Your energy levels could use some support. Focus on sleep quality and balanced nutrition.',
        mental: 'Some stress or mood concerns noted. Consider mindfulness practices and adequate rest.',
        hormonal: 'Some hormonal imbalance indicators present. A targeted nutrition plan may help.',
        immune: 'Your immune system may need extra support. Focus on nutrient-dense foods and rest.',
      },
      high: {
        digestive: 'Significant digestive concerns identified. Professional guidance is recommended.',
        energy: 'Severe fatigue or energy issues detected. Consult with a healthcare provider.',
        mental: 'High stress or mood concerns present. Professional support may be beneficial.',
        hormonal: 'Significant hormonal imbalance indicators. Medical evaluation recommended.',
        immune: 'Your immune system appears compromised. Seek professional health guidance.',
      },
    };

    return interpretations[severity]?.[primaryConcern] || 
           'Based on your responses, a personalized consultation would be beneficial.';
  }

  async generateRecommendations(score: number, analysis: any) {
    const recommendations: any[] = [];

    // Program recommendations based on primary concern
    const programMap: Record<string, string> = {
      digestive: 'GUT_HEALTH',
      energy: 'METABOLIC_RESET',
      hormonal: 'PCOS_RESTORE',
      mental: 'STRESS_MANAGEMENT',
      immune: 'DETOX_HORMONE',
    };

    if (analysis.primaryConcern && programMap[analysis.primaryConcern]) {
      recommendations.push({
        type: 'program',
        priority: 'high',
        programType: programMap[analysis.primaryConcern],
        message: `Based on your ${analysis.primaryConcern} concerns, our ${programMap[analysis.primaryConcern].replace('_', ' ')} program may be ideal for you.`,
      });
    }

    // Lifestyle recommendations
    if (analysis.severity === 'moderate' || analysis.severity === 'high') {
      recommendations.push({
        type: 'consultation',
        priority: analysis.severity === 'high' ? 'urgent' : 'medium',
        message: 'A personalized consultation can help address your specific health concerns.',
      });
    }

    // Category-specific recommendations
    Object.entries(analysis.categoryBreakdown).forEach(([category, score]) => {
      if (score > 5) {
        recommendations.push(...this.getCategoryRecommendations(category, score));
      }
    });

    return recommendations;
  }

  private getCategoryRecommendations(category: string, score: number): any[] {
    const recommendations: Record<string, any[]> = {
      digestive: [
        {
          type: 'lifestyle',
          title: 'Improve Gut Health',
          suggestions: [
            'Include fermented foods daily',
            'Increase fiber intake gradually',
            'Stay hydrated with 8-10 glasses of water',
            'Consider a food sensitivity test',
          ],
        },
        {
          type: 'resource',
          title: '7-Day Gut Reset Guide',
          resourceId: 'gut-reset-guide',
        },
      ],
      energy: [
        {
          type: 'lifestyle',
          title: 'Boost Energy Naturally',
          suggestions: [
            'Prioritize 7-8 hours of quality sleep',
            'Balance blood sugar with protein at each meal',
            'Consider B-vitamin supplementation',
            'Reduce caffeine dependency',
          ],
        },
        {
          type: 'calculator',
          title: 'Calculate Your Ideal Macros',
          toolId: 'macro-calculator',
        },
      ],
      // ... other categories
    };

    return recommendations[category] || [];
  }
}
```

### Day 4-7: Recommendation Engine

#### 1. Recommendation Service
```typescript
// services/quiz/src/services/recommendation.service.ts
import { prisma } from '@nutrition/database';
import { MachineLearningService } from './ml.service';
import { ContentBasedFilter } from '../algorithms/content-based.filter';
import { CollaborativeFilter } from '../algorithms/collaborative.filter';

export class RecommendationService {
  static async generateRecommendations(quizResult: any) {
    const userId = quizResult.userId;
    const analysis = quizResult.analysis;

    // Get user history if authenticated
    let userHistory = null;
    if (userId) {
      userHistory = await this.getUserHistory(userId);
    }

    // Generate different types of recommendations
    const [
      programRecommendations,
      contentRecommendations,
      nutritionistRecommendations,
      resourceRecommendations,
    ] = await Promise.all([
      this.recommendPrograms(analysis, userHistory),
      this.recommendContent(analysis, userHistory),
      this.recommendNutritionists(analysis, userId),
      this.recommendResources(analysis),
    ]);

    // Combine and prioritize recommendations
    const combinedRecommendations = this.prioritizeRecommendations({
      programs: programRecommendations,
      content: contentRecommendations,
      nutritionists: nutritionistRecommendations,
      resources: resourceRecommendations,
    });

    // Track recommendations for analytics
    if (userId) {
      await this.trackRecommendations(userId, combinedRecommendations);
    }

    return combinedRecommendations;
  }

  private static async recommendPrograms(analysis: any, userHistory: any) {
    // Get all active programs
    const programs = await prisma.program.findMany({
      where: { isActive: true },
      include: {
        reviews: {
          select: { rating: true },
        },
      },
    });

    // Score programs based on analysis
    const scoredPrograms = programs.map((program) => {
      let score = 0;

      // Match program type with primary concern
      if (this.matchProgramToConcern(program.type, analysis.primaryConcern)) {
        score += 50;
      }

      // Consider secondary concerns
      analysis.secondaryConcerns.forEach((concern: string) => {
        if (this.matchProgramToConcern(program.type, concern)) {
          score += 20;
        }
      });

      // Factor in program ratings
      const avgRating = program.reviews.length > 0
        ? program.reviews.reduce((sum, r) => sum + r.rating, 0) / program.reviews.length
        : 3;
      score += avgRating * 10;

      // User history considerations
      if (userHistory) {
        // Avoid recommending completed programs
        if (userHistory.completedPrograms.includes(program.id)) {
          score -= 100;
        }
        // Boost programs similar to previously successful ones
        if (userHistory.successfulPrograms.includes(program.type)) {
          score += 30;
        }
      }

      return { ...program, score };
    });

    // Sort and return top programs
    return scoredPrograms
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(({ score, ...program }) => ({
        ...program,
        reason: this.generateProgramReason(program, analysis),
        confidence: Math.min(score / 100, 1),
      }));
  }

  private static async recommendContent(analysis: any, userHistory: any) {
    // Use content-based filtering
    const contentFilter = new ContentBasedFilter();
    
    // Get user interests from analysis
    const interests = this.extractInterestsFromAnalysis(analysis);

    // Get relevant blog posts
    const blogPosts = await prisma.blogPost.findMany({
      where: {
        isPublished: true,
        OR: interests.map((interest) => ({
          tags: { has: interest },
        })),
      },
      orderBy: { publishedAt: 'desc' },
      take: 20,
    });

    // Score and filter content
    const scoredContent = await contentFilter.scoreContent(
      blogPosts,
      interests,
      userHistory
    );

    return scoredContent.slice(0, 5);
  }

  private static async recommendNutritionists(analysis: any, userId?: string) {
    const nutritionists = await prisma.nutritionistProfile.findMany({
      where: { isActive: true },
      include: {
        user: {
          include: { profile: true },
        },
      },
    });

    // Score nutritionists based on specialization match
    const scored = nutritionists.map((nutritionist) => {
      let score = 0;

      // Match specializations with concerns
      const relevantSpecs = this.getRelevantSpecializations(analysis);
      relevantSpecs.forEach((spec) => {
        if (nutritionist.specializations.includes(spec)) {
          score += 30;
        }
      });

      // Consider ratings
      score += nutritionist.rating * 10;

      // Language preferences
      if (userId) {
        // Would check user's language preference
        score += 10;
      }

      return { ...nutritionist, score };
    });

    return scored
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(({ score, ...nutritionist }) => ({
        ...nutritionist,
        matchPercentage: Math.min((score / 100) * 100, 95),
      }));
  }

  private static async recommendResources(analysis: any) {
    const resourceTypes = this.getRelevantResourceTypes(analysis);

    const resources = await prisma.resource.findMany({
      where: {
        type: { in: resourceTypes },
        isPublic: true,
      },
      orderBy: { downloadCount: 'desc' },
      take: 10,
    });

    // Filter based on analysis
    return resources.filter((resource) => {
      const tags = resource.tags || [];
      return tags.some((tag) => 
        this.isTagRelevant(tag, analysis)
      );
    }).slice(0, 3);
  }

  private static prioritizeRecommendations(recommendations: any) {
    const prioritized: any[] = [];

    // High priority: Urgent health concerns
    if (recommendations.programs.some((p: any) => p.confidence > 0.8)) {
      prioritized.push({
        type: 'action',
        priority: 'high',
        title: 'Recommended Program',
        item: recommendations.programs[0],
        cta: 'Learn More',
      });
    }

    // Medium priority: Educational content
    recommendations.content.forEach((content: any, index: number) => {
      if (index < 2) {
        prioritized.push({
          type: 'content',
          priority: 'medium',
          title: content.title,
          item: content,
          cta: 'Read Article',
        });
      }
    });

    // Consultation recommendation if severity is high
    const shouldRecommendConsultation = true; // Based on analysis
    if (shouldRecommendConsultation) {
      prioritized.push({
        type: 'consultation',
        priority: 'high',
        title: 'Book a Free Discovery Call',
        item: {
          description: 'Get personalized guidance from our expert nutritionists',
          nutritionists: recommendations.nutritionists.slice(0, 2),
        },
        cta: 'Book Now',
      });
    }

    return prioritized;
  }

  private static async getUserHistory(userId: string) {
    const [journeys, quizResults, viewedContent] = await Promise.all([
      prisma.userJourney.findMany({
        where: { userId },
        include: { program: true },
      }),
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        take: 10,
      }),
      // Would fetch from analytics/audit logs
      [],
    ]);

    return {
      completedPrograms: journeys
        .filter((j) => j.status === 'COMPLETED')
        .map((j) => j.programId),
      successfulPrograms: journeys
        .filter((j) => j.status === 'COMPLETED' && j.progress?.satisfaction > 7)
        .map((j) => j.program.type),
      quizHistory: quizResults,
      viewedContent,
    };
  }

  private static matchProgramToConcern(programType: string, concern: string): boolean {
    const mapping: Record<string, string[]> = {
      GUT_HEALTH: ['digestive', 'bloating', 'ibs'],
      METABOLIC_RESET: ['energy', 'weight', 'metabolism'],
      PCOS_RESTORE: ['hormonal', 'pcos', 'fertility'],
      DIABETES_CARE: ['diabetes', 'blood_sugar', 'insulin'],
      DETOX_HORMONE: ['detox', 'hormonal', 'immune'],
    };

    return mapping[programType]?.includes(concern) || false;
  }

  private static generateProgramReason(program: any, analysis: any): string {
    const templates = [
      `Perfect for addressing your ${analysis.primaryConcern} concerns`,
      `${program._count?.journeys || 0} people with similar symptoms found success`,
      `Specifically designed for ${analysis.severity} ${analysis.primaryConcern} issues`,
    ];

    return templates[Math.floor(Math.random() * templates.length)];
  }

  private static extractInterestsFromAnalysis(analysis: any): string[] {
    const interests: string[] = [];

    // Map concerns to interests
    const concernToInterests: Record<string, string[]> = {
      digestive: ['gut-health', 'probiotics', 'digestion', 'ibs'],
      energy: ['metabolism', 'fatigue', 'nutrition', 'vitamins'],
      hormonal: ['hormones', 'pcos', 'thyroid', 'womens-health'],
      mental: ['stress', 'anxiety', 'mood', 'mindfulness'],
      immune: ['immunity', 'inflammation', 'detox', 'antioxidants'],
    };

    if (analysis.primaryConcern) {
      interests.push(...(concernToInterests[analysis.primaryConcern] || []));
    }

    analysis.secondaryConcerns.forEach((concern: string) => {
      interests.push(...(concernToInterests[concern] || []));
    });

    return [...new Set(interests)];
  }

  private static getRelevantSpecializations(analysis: any): string[] {
    const specs: string[] = [];

    if (analysis.primaryConcern === 'digestive') {
      specs.push('Gut Health', 'IBS Management');
    }
    if (analysis.primaryConcern === 'hormonal') {
      specs.push('Hormonal Balance', 'PCOS');
    }
    // ... more mappings

    return specs;
  }

  private static getRelevantResourceTypes(analysis: any): string[] {
    if (analysis.severity === 'high') {
      return ['tracker', 'guide', 'meal_plan'];
    }
    return ['guide', 'calculator', 'ebook'];
  }

  private static isTagRelevant(tag: string, analysis: any): boolean {
    const relevantTags = this.extractInterestsFromAnalysis(analysis);
    return relevantTags.some((interest) => 
      tag.toLowerCase().includes(interest.toLowerCase())
    );
  }

  private static async trackRecommendations(userId: string, recommendations: any[]) {
    // Store recommendations for analytics and ML training
    await prisma.recommendationLog.create({
      data: {
        userId,
        recommendations: recommendations,
        context: 'quiz_result',
        createdAt: new Date(),
      },
    });
  }
}
```

## Week 7: Content Management & PayloadCMS Integration

### Day 1-3: PayloadCMS Setup and Configuration

#### 1. PayloadCMS Configuration
```typescript
// apps/admin/src/payload.config.ts
import { buildConfig } from 'payload/config';
import path from 'path';
import { cloudStorage } from '@payloadcms/plugin-cloud-storage';
import { s3Adapter } from '@payloadcms/plugin-cloud-storage/s3';
import { seo } from '@payloadcms/plugin-seo';
import { formBuilder } from '@payloadcms/plugin-form-builder';

#### 1. Journey Controller
```typescript
// services/user/src/controllers/journey.controller.ts
import { Request, Response, NextFunction } from 'express';
import { JourneyService } from '../services/journey.service';
import { AppError } from '../utils/errors';

export class JourneyController {
  static async getCurrentJourney(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const journey = await JourneyService.getCurrentJourney(userId);

      res.json({
        success: true,
        data: journey,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getJourneyHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const journeys = await JourneyService.getJourneyHistory(userId);

      res.json({
        success: true,
        data: journeys,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createCheckIn(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const checkInData = req.body;

      const checkIn = await JourneyService.createCheckIn(userId, checkInData);

      res.json({
        success: true,
        message: 'Check-in recorded successfully',
        data: checkIn,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getCheckIns(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { journeyId } = req.params;
      const { startDate, endDate } = req.query;

      const checkIns = await JourneyService.getCheckIns(journeyId, userId, {
        startDate: startDate as string,
        endDate: endDate as string,
      });

      res.json({
        success: true,
        data: checkIns,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createMealEntry(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const mealData = req.body;

      const meal = await JourneyService.createMealEntry(userId, mealData);

      res.json({
        success: true,
        message: 'Meal entry recorded successfully',
        data: meal,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getMealEntries(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { date } = req.query;

      const meals = await JourneyService.getMealEntries(
        userId,
        date ? new Date(date as string) : new Date()
      );

      res.json({
        success: true,
        data: meals,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgressReport(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { journeyId } = req.params;

      const report = await JourneyService.generateProgressReport(journeyId, userId);

      res.json({
        success: true,
        data: report,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateMeasurements(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const measurements = req.body;

      const updated = await JourneyService.updateMeasurements(userId, measurements);

      res.json({
        success: true,
        message: 'Measurements updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Journey Service
```typescript
// services/user/src/services/journey.service.ts
import { prisma } from '@nutrition/database';
import { calculateCalories, analyzeMacros } from '../utils/nutrition.calculations';
import { generateChartData } from '../utils/chart.utils';

export class JourneyService {
  static async getCurrentJourney(userId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
      include: {
        program: true,
        checkIns: {
          orderBy: { date: 'desc' },
          take: 7,
        },
        mealEntries: {
          where: {
            date: {
              gte: new Date(new Date().setHours(0, 0, 0, 0)),
            },
          },
        },
      },
    });

    if (!journey) {
      return null;
    }

    // Calculate progress
    const totalDays = journey.program.duration;
    const elapsedDays = Math.floor(
      (new Date().getTime() - journey.startDate.getTime()) / (1000 * 60 * 60 * 24)
    );
    const progressPercentage = Math.min((elapsedDays / totalDays) * 100, 100);

    // Calculate today's nutrition
    const todayNutrition = this.calculateDailyNutrition(journey.mealEntries);

    return {
      ...journey,
      progress: {
        percentage: progressPercentage,
        elapsedDays,
        remainingDays: Math.max(totalDays - elapsedDays, 0),
      },
      todayNutrition,
    };
  }

  static async getJourneyHistory(userId: string) {
    return prisma.userJourney.findMany({
      where: { userId },
      include: {
        program: true,
        payments: {
          where: { status: 'SUCCESS' },
        },
      },
      orderBy: { startDate: 'desc' },
    });
  }

  static async createCheckIn(userId: string, data: any) {
    // Get active journey
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    // Create check-in
    const checkIn = await prisma.journeyCheckIn.create({
      data: {
        journeyId: journey.id,
        date: new Date(),
        ...data,
      },
    });

    // Update journey measurements if weight is provided
    if (data.weight) {
      await this.updateJourneyMeasurements(journey.id, { weight: data.weight });
    }

    return checkIn;
  }

  static async getCheckIns(journeyId: string, userId: string, filters: any) {
    // Verify journey belongs to user
    const journey = await prisma.userJourney.findFirst({
      where: {
        id: journeyId,
        userId,
      },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    const where: any = { journeyId };

    if (filters.startDate) {
      where.date = { gte: new Date(filters.startDate) };
    }

    if (filters.endDate) {
      where.date = { ...where.date, lte: new Date(filters.endDate) };
    }

    return prisma.journeyCheckIn.findMany({
      where,
      orderBy: { date: 'desc' },
    });
  }

  static async createMealEntry(userId: string, data: any) {
    // Get active journey
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    // Calculate nutrition info
    const nutritionInfo = await calculateCalories(data.foods);

    return prisma.mealEntry.create({
      data: {
        journeyId: journey.id,
        date: new Date(),
        mealType: data.mealType,
        foods: data.foods,
        ...nutritionInfo,
        notes: data.notes,
        photo: data.photo,
      },
    });
  }

  static async getMealEntries(userId: string, date: Date) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      return [];
    }

    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);

    return prisma.mealEntry.findMany({
      where: {
        journeyId: journey.id,
        date: {
          gte: startOfDay,
          lte: endOfDay,
        },
      },
      orderBy: { date: 'asc' },
    });
  }

  static async generateProgressReport(journeyId: string, userId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        id: journeyId,
        userId,
      },
      include: {
        program: true,
        checkIns: {
          orderBy: { date: 'asc' },
        },
        mealEntries: {
          orderBy: { date: 'asc' },
        },
      },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    // Generate various analytics
    const weightProgress = generateChartData(
      journey.checkIns.filter(c => c.weight),
      'date',
      'weight'
    );

    const energyTrend = generateChartData(
      journey.checkIns.filter(c => c.energy),
      'date',
      'energy'
    );

    const nutritionSummary = analyzeMacros(journey.mealEntries);

    // Calculate achievements
    const achievements = this.calculateAchievements(journey);

    return {
      journey: {
        id: journey.id,
        program: journey.program.name,
        startDate: journey.startDate,
        progress: journey.progress,
      },
      charts: {
        weightProgress,
        energyTrend,
      },
      nutritionSummary,
      achievements,
      recommendations: this.generateRecommendations(journey),
    };
  }

  static async updateMeasurements(userId: string, measurements: any) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    return this.updateJourneyMeasurements(journey.id, measurements);
  }

  private static async updateJourneyMeasurements(journeyId: string, measurements: any) {
    const journey = await prisma.userJourney.findUnique({
      where: { id: journeyId },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    const currentMeasurements = journey.measurements || {};
    const updatedMeasurements = {
      ...currentMeasurements,
      ...measurements,
      lastUpdated: new Date(),
    };

    return prisma.userJourney.update({
      where: { id: journeyId },
      data: { measurements: updatedMeasurements },
    });
  }

  private static calculateDailyNutrition(mealEntries: any[]) {
    return mealEntries.reduce(
      (total, meal) => ({
        calories: total.calories + (meal.calories || 0),
        protein: total.protein + (meal.protein || 0),
        carbs: total.carbs + (meal.carbs || 0),
        fat: total.fat + (meal.fat || 0),
        fiber: total.fiber + (meal.fiber || 0),
      }),
      { calories: 0, protein: 0, carbs: 0, fat: 0, fiber: 0 }
    );
  }

  private static calculateAchievements(journey: any) {
    const achievements = [];

    // Check-in streak
    const checkInDates = journey.checkIns.map((c: any) => 
      new Date(c.date).toDateString()
    );
    const uniqueDates = [...new Set(checkInDates)];
    
    if (uniqueDates.length >= 7) {
      achievements.push({
        type: 'streak',
        title: 'Week Warrior',
        description: 'Checked in for 7 days',
      });
    }

    // Weight loss
    if (journey.checkIns.length > 1) {
      const firstWeight = journey.checkIns[0].weight;
      const lastWeight = journey.checkIns[journey.checkIns.length - 1].weight;
      
      if (firstWeight && lastWeight && lastWeight < firstWeight) {
        const loss = firstWeight - lastWeight;
        achievements.push({
          type: 'weight_loss',
          title: 'Progress Made',
          description: `Lost ${loss.toFixed(1)} kg`,
        });
      }
    }

    return achievements;
  }

  private static generateRecommendations(journey: any) {
    const recommendations = [];

    // Analyze recent check-ins
    const recentCheckIns = journey.checkIns.slice(-7);
    const avgEnergy = recentCheckIns.reduce((sum: number, c: any) => 
      sum + (c.energy || 0), 0
    ) / recentCheckIns.length;

    if (avgEnergy < 5) {
      recommendations.push({
        type: 'energy',
        priority: 'high',
        message: 'Your energy levels seem low. Consider reviewing your sleep schedule and stress management.',
      });
    }

    // Analyze nutrition
    const recentMeals = journey.mealEntries.slice(-21); // Last week
    const avgProtein = recentMeals.reduce((sum: number, m: any) => 
      sum + (m.protein || 0), 0
    ) / recentMeals.length;

    if (avgProtein < 20) {
      recommendations.push({
        type: 'nutrition',
        priority: 'medium',
        message: 'Your protein intake appears low. Try to include more protein-rich foods in your meals.',
      });
    }

    return recommendations;
  }
}
```

## Week 4: Program & Consultation Management

### Day 1-2: Program Service

#### 1. Program Controller
```typescript
// services/consultation/src/controllers/program.controller.ts
import { Request, Response, NextFunction } from 'express';
import { ProgramService } from '../services/program.service';
import { AppError } from '../utils/errors';

export class ProgramController {
  static async getAllPrograms(req: Request, res: Response, next: NextFunction) {
    try {
      const { type, featured, page = 1, limit = 10 } = req.query;

      const programs = await ProgramService.getAllPrograms({
        type: type as string,
        featured: featured === 'true',
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: programs,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramBySlug(req: Request, res: Response, next: NextFunction) {
    try {
      const { slug } = req.params;
      const userId = req.user?.userId;

      const program = await ProgramService.getProgramBySlug(slug, userId);

      if (!program) {
        throw new AppError('Program not found', 404);
      }

      res.json({
        success: true,
        data: program,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramDetails(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const details = await ProgramService.getProgramDetails(id, userId);

      res.json({
        success: true,
        data: details,
      });
    } catch (error) {
      next(error);
    }
  }

  static async enrollInProgram(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { startDate } = req.body;

      const enrollment = await ProgramService.enrollInProgram(userId, id, startDate);

      res.json({
        success: true,
        message: 'Successfully enrolled in program',
        data: enrollment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getRecommendedPrograms(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.user?.userId;

      const recommendations = await ProgramService.getRecommendedPrograms(userId);

      res.json({
        success: true,
        data: recommendations,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createReview(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { rating, title, comment } = req.body;

      const review = await ProgramService.createReview(userId, id, {
        rating,
        title,
        comment,
      });

      res.json({
        success: true,
        message: 'Review submitted successfully',
        data: review,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramReviews(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { page = 1, limit = 10 } = req.query;

      const reviews = await ProgramService.getProgramReviews(id, {
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: reviews,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Program Service
```typescript
// services/consultation/src/services/program.service.ts
import { prisma } from '@nutrition/database';
import { cacheManager } from '../utils/cache';
import { calculateProgramScore } from '../utils/recommendation.engine';

export class ProgramService {
  private static readonly CACHE_PREFIX = 'program:';
  private static readonly CACHE_TTL = 3600; // 1 hour

  static async getAllPrograms(options: {
    type?: string;
    featured?: boolean;
    page: number;
    limit: number;
  }) {
    const where: any = {
      isActive: true,
    };

    if (options.type) {
      where.type = options.type;
    }

    if (options.featured !== undefined) {
      where.isFeatured = options.featured;
    }

    const [programs, total] = await Promise.all([
      prisma.program.findMany({
        where,
        orderBy: [
          { isFeatured: 'desc' },
          { order: 'asc' },
          { createdAt: 'desc' },
        ],
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          _count: {
            select: {
              reviews: true,
              journeys: true,
            },
          },
        },
      }),
      prisma.program.count({ where }),
    ]);

    // Calculate average ratings
    const programsWithRatings = await Promise.all(
      programs.map(async (program) => {
        const avgRating = await prisma.programReview.aggregate({
          where: { programId: program.id },
          _avg: { rating: true },
        });

        return {
          ...program,
          averageRating: avgRating._avg.rating || 0,
        };
      })
    );

    return {
      programs: programsWithRatings,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getProgramBySlug(slug: string, userId?: string) {
    // Try cache first
    const cacheKey = `${this.CACHE_PREFIX}slug:${slug}`;
    const cached = await cacheManager.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const program = await prisma.program.findUnique({
      where: { slug, isActive: true },
      include: {
        reviews: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          include: {
            user: {
              select: {
                profile: {
                  select: {
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            },
          },
        },
        _count: {
          select: {
            reviews: true,
            journeys: true,
          },
        },
      },
    });

    if (!program) {
      return null;
    }

    // Calculate stats
    const [avgRating, completionRate] = await Promise.all([
      prisma.programReview.aggregate({
        where: { programId: program.id },
        _avg: { rating: true },
      }),
      this.calculateCompletionRate(program.id),
    ]);

    const enrichedProgram = {
      ...program,
      stats: {
        averageRating: avgRating._avg.rating || 0,
        totalReviews: program._count.reviews,
        totalEnrollments: program._count.journeys,
        completionRate,
      },
    };

    // Cache the result
    await cacheManager.set(cacheKey, JSON.stringify(enrichedProgram), this.CACHE_TTL);

    // Track view if user is logged in
    if (userId) {
      await this.trackProgramView(userId, program.id);
    }

    return enrichedProgram;
  }

  static async getProgramDetails(programId: string, userId?: string) {
    const program = await prisma.program.findUnique({
      where: { id: programId, isActive: true },
    });

    if (!program) {
      throw new Error('Program not found');
    }

    // Get detailed information
    const [
      weeklySchedule,
      sampleMealPlan,
      successStories,
      faqs,
      userProgress,
    ] = await Promise.all([
      this.getWeeklySchedule(programId),
      this.getSampleMealPlan(program.type),
      this.getSuccessStories(programId),
      this.getProgramFAQs(program.type),
      userId ? this.getUserProgramProgress(userId, programId) : null,
    ]);

    return {
      program,
      details: {
        weeklySchedule,
        sampleMealPlan,
        successStories,
        faqs,
      },
      userProgress,
    };
  }

  static async enrollInProgram(userId: string, programId: string, startDate?: Date) {
    // Check if already enrolled
    const existingJourney = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
        status: { in: ['ACTIVE', 'PAUSED'] },
      },
    });

    if (existingJourney) {
      throw new Error('Already enrolled in this program');
    }

    // Get program details
    const program = await prisma.program.findUnique({
      where: { id: programId },
    });

    if (!program) {
      throw new Error('Program not found');
    }

    // Create journey
    const journey = await prisma.userJourney.create({
      data: {
        userId,
        programId,
        startDate: startDate || new Date(),
        endDate: null, // Will be calculated based on progress
        status: 'ACTIVE',
        progress: {
          currentWeek: 1,
          completedModules: [],
          milestones: [],
        },
      },
    });

    // Create initial meal plan
    await this.createInitialMealPlan(journey.id, program.type);

    // Schedule welcome email
    await this.scheduleWelcomeSequence(userId, programId);

    return journey;
  }

  static async getRecommendedPrograms(userId?: string) {
    if (!userId) {
      // Return popular programs for non-authenticated users
      return this.getPopularPrograms();
    }

    // Get user data for recommendation
    const [userData, quizResults, previousPrograms] = await Promise.all([
      prisma.user.findUnique({
        where: { id: userId },
        include: {
          profile: true,
          journeys: {
            include: { program: true },
          },
        },
      }),
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        take: 5,
      }),
      prisma.userJourney.findMany({
        where: { userId },
        include: { program: true },
      }),
    ]);

    if (!userData) {
      return this.getPopularPrograms();
    }

    // Get all active programs
    const programs = await prisma.program.findMany({
      where: { isActive: true },
      include: {
        _count: {
          select: {
            reviews: true,
            journeys: true,
          },
        },
      },
    });

    // Score each program based on user data
    const scoredPrograms = programs.map((program) => ({
      ...program,
      score: calculateProgramScore(program, {
        userData,
        quizResults,
        previousPrograms,
      }),
    }));

    // Sort by score and return top 5
    return scoredPrograms
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map(({ score, ...program }) => program);
  }

  static async createReview(userId: string, programId: string, data: {
    rating: number;
    title?: string;
    comment?: string;
  }) {
    // Check if user has completed the program
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
        status: 'COMPLETED',
      },
    });

    if (!journey) {
      throw new Error('You must complete the program before reviewing');
    }

    // Check if already reviewed
    const existingReview = await prisma.programReview.findUnique({
      where: {
        programId_userId: {
          programId,
          userId,
        },
      },
    });

    if (existingReview) {
      throw new Error('You have already reviewed this program');
    }

    // Create review
    const review = await prisma.programReview.create({
      data: {
        programId,
        userId,
        rating: data.rating,
        title: data.title,
        comment: data.comment,
        isVerified: true, // Since they completed the program
      },
    });

    // Update program rating cache
    await this.updateProgramRatingCache(programId);

    return review;
  }

  static async getProgramReviews(programId: string, options: {
    page: number;
    limit: number;
  }) {
    const [reviews, total] = await Promise.all([
      prisma.programReview.findMany({
        where: { programId },
        orderBy: [
          { isVerified: 'desc' },
          { createdAt: 'desc' },
        ],
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          user: {
            select: {
              profile: {
                select: {
                  firstName: true,
                  lastName: true,
                  avatar: true,
                },
              },
            },
          },
        },
      }),
      prisma.programReview.count({ where: { programId } }),
    ]);

    // Get rating distribution
    const ratingDistribution = await prisma.programReview.groupBy({
      by: ['rating'],
      where: { programId },
      _count: true,
    });

    return {
      reviews,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
      stats: {
        distribution: ratingDistribution.reduce((acc, item) => {
          acc[item.rating] = item._count;
          return acc;
        }, {} as Record<number, number>),
      },
    };
  }

  private static async calculateCompletionRate(programId: string) {
    const journeys = await prisma.userJourney.findMany({
      where: { programId },
      select: { status: true },
    });

    if (journeys.length === 0) return 0;

    const completed = journeys.filter(j => j.status === 'COMPLETED').length;
    return Math.round((completed / journeys.length) * 100);
  }

  private static async getPopularPrograms() {
    return prisma.program.findMany({
      where: { isActive: true, isFeatured: true },
      orderBy: { order: 'asc' },
      take: 5,
    });
  }

  private static async trackProgramView(userId: string, programId: string) {
    // Implement view tracking for analytics
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'VIEW_PROGRAM',
        entity: 'program',
        entityId: programId,
      },
    });
  }

  private static async getWeeklySchedule(programId: string) {
    // This would be stored in program metadata or a separate table
    // For now, returning a sample structure
    return {
      week1: {
        title: 'Foundation Week',
        activities: [
          'Initial health assessment',
          'Personalized meal plan creation',
          'Introduction to food journaling',
        ],
      },
      week2: {
        title: 'Implementation Week',
        activities: [
          'Start meal plan',
          'Daily check-ins',
          'First consultation call',
        ],
      },
      // ... more weeks
    };
  }

  private static async getSampleMealPlan(programType: string) {
    // Fetch from a meal plan service or database
    // This is a simplified example
    const mealPlans: Record<string, any> = {
      GUT_HEALTH: {
        day1: {
          breakfast: 'Overnight oats with chia seeds and berries',
          lunch: 'Grilled chicken salad with fermented vegetables',
          dinner: 'Baked salmon with steamed broccoli and quinoa',
          snacks: ['Apple slices with almond butter', 'Kefir smoothie'],
        },
        // ... more days
      },
      // ... other program types
    };

    return mealPlans[programType] || {};
  }

  private static async getSuccessStories(programId: string) {
    return prisma.programReview.findMany({
      where: {
        programId,
        rating: { gte: 4 },
        comment: { not: null },
        isVerified: true,
      },
      select: {
        rating: true,
        title: true,
        comment: true,
        createdAt: true,
        user: {
          select: {
            profile: {
              select: {
                firstName: true,
              },
            },
          },
        },
      },
      take: 3,
      orderBy: { rating: 'desc' },
    });
  }

  private static async getProgramFAQs(programType: string) {
    // This would be fetched from a CMS or database
    // Simplified example
    const faqs: Record<string, any[]> = {
      GUT_HEALTH: [
        {
          question: 'How long before I see results?',
          answer: 'Most clients report improvements in bloating and digestion within 2-3 weeks.',
        },
        {
          question: 'Can I follow this program if I have food allergies?',
          answer: 'Yes, all meal plans are customized based on your dietary restrictions.',
        },
      ],
      // ... other types
    };

    return faqs[programType] || [];
  }

  private static async getUserProgramProgress(userId: string, programId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!journey) {
      return null;
    }

    return {
      status: journey.status,
      startDate: journey.startDate,
      progress: journey.progress,
      completedAt: journey.completedAt,
    };
  }

  private static async createInitialMealPlan(journeyId: string, programType: string) {
    // This would integrate with a meal planning service
    // For now, we'll store a reference in the journey
    await prisma.userJourney.update({
      where: { id: journeyId },
      data: {
        mealPlans: {
          week1: 'Generated based on program type',
          status: 'pending_nutritionist_review',
        },
      },
    });
  }

  private static async scheduleWelcomeSequence(userId: string, programId: string) {
    // Schedule a series of welcome emails
    const emailSequence = [
      { delay: 0, template: 'program_welcome' },
      { delay: 1, template: 'program_day1_tips' },
      { delay: 3, template: 'program_check_in' },
      { delay: 7, template: 'program_week1_summary' },
    ];

    for (const email of emailSequence) {
      await prisma.notification.create({
        data: {
          userId,
          type: 'email',
          category: 'journey',
          title: `Program Email - ${email.template}`,
          content: JSON.stringify({ programId, template: email.template }),
          status: 'PENDING',
          createdAt: new Date(Date.now() + email.delay * 24 * 60 * 60 * 1000),
        },
      });
    }
  }

  private static async updateProgramRatingCache(programId: string) {
    const avgRating = await prisma.programReview.aggregate({
      where: { programId },
      _avg: { rating: true },
      _count: true,
    });

    // Update cache
    const cacheKey = `${this.CACHE_PREFIX}rating:${programId}`;
    await cacheManager.set(
      cacheKey,
      JSON.stringify({
        average: avgRating._avg.rating || 0,
        count: avgRating._count,
      }),
      86400 // 24 hours
    );
  }
}: '<rootDir>/packages/$1/src',
  },
  moduleDirectories: ['node_modules', '<rootDir>/'],
  testEnvironment: 'jest-environment-jsdom',
  testMatch: [
    '**/__tests__/**/*.(test|spec).(ts|tsx|js)',
    '**/*.(test|spec).(ts|tsx|js)',
  ],
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/index.{js,jsx,ts,tsx}',
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70,
    },
  },
};

module.exports = createJestConfig(customJestConfig);
```

#### 2. Testing Examples
```typescript
// services/auth/src/services/__tests__/password.service.test.ts
import { PasswordService } from '../password.service';
import bcrypt from 'bcrypt';
import { redisClient } from '../../utils/redis';

jest.mock('bcrypt');
jest.mock('../../utils/redis');

describe('PasswordService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('hash', () => {
    it('should hash password with correct salt rounds', async () => {
      const password = 'Test@123';
      const hashedPassword = 'hashed_password';
      
      (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword);

      const result = await PasswordService.hash(password);

      expect(bcrypt.hash).toHaveBeenCalledWith(password, 12);
      expect(result).toBe(hashedPassword);
    });
  });

  describe('validateStrength', () => {
    it('should validate strong password', () => {
      const result = PasswordService.validateStrength('Test@123');
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject weak password', () => {
      const result = PasswordService.validateStrength('weak');
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must be at least 8 characters long');
      expect(result.errors).toContain('Password must contain at least one uppercase letter');
      expect(result.errors).toContain('Password must contain at least one number');
      expect(result.errors).toContain('Password must contain at least one special character');
    });
  });

  describe('generateResetToken', () => {
    it('should generate and store reset token', async () => {
      const userId = 'user123';
      const mockSetex = jest.fn();
      
      (redisClient.setex as jest.Mock) = mockSetex;

      const token = await PasswordService.generateResetToken(userId);

      expect(token).toHaveLength(64);
      expect(mockSetex).toHaveBeenCalled();
      expect(mockSetex.mock.calls[0][1]).toBe(3600); // 1 hour expiry
      expect(mockSetex.mock.calls[0][2]).toBe(userId);
    });
  });
});
```

### Day 3-4: E2E Testing

#### 1. Playwright Configuration
```typescript
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: process.env.PLAYWRIGHT_TEST_BASE_URL || 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
  ],

  webServer: {
    command: 'npm run dev',
    port: 3000,
    reuseExistingServer: !process.env.CI,
  },
});
```

#### 2. E2E Test Examples
```typescript
// tests/e2e/auth.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test('user can register successfully', async ({ page }) => {
    await page.goto('/register');

    // Fill registration form
    await page.fill('input[name="email"]', 'test@example.com');
    await page.fill('input[name="password"]', 'Test@123456');
    await page.fill('input[name="firstName"]', 'Test');
    await page.fill('input[name="lastName"]', 'User');
    await page.check('input[name="acceptTerms"]');

    // Submit form
    await page.click('button[type="submit"]');

    // Verify redirect to dashboard
    await expect(page).toHaveURL('/dashboard');
    await expect(page.locator('text=Welcome, Test!')).toBeVisible();
  });

  test('user can login with valid credentials', async ({ page }) => {
    await page.goto('/login');

    await page.fill('input[name="email"]', 'existing@example.com');
    await page.fill('input[name="password"]', 'Test@123456');
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL('/dashboard');
  });

  test('shows error for invalid credentials', async ({ page }) => {
    await page.goto('/login');

    await page.fill('input[name="email"]', 'wrong@example.com');
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    await expect(page.locator('text=Invalid email or password')).toBeVisible();
  });
});

// tests/e2e/consultation-booking.spec.ts
test.describe('Consultation Booking', () => {
  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto('/login');
    await page.fill('input[name="email"]', 'test@example.com');
    await page.fill('input[name="password"]', 'Test@123456');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard');
  });

  test('user can book a consultation', async ({ page }) => {
    await page.goto('/dashboard/consultations/book');

    // Select nutritionist
    await page.click('text=Dr. Sarah Johnson');

    // Select date (tomorrow)
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    await page.click(`[aria-label="${tomorrow.toDateString()}"]`);

    // Select time slot
    await page.click('text=10:00 AM');

    // Add notes
    await page.fill('textarea', 'I need help with digestive issues');

    // Confirm booking
    await page.click('text=Confirm Booking');

    // Verify success
    await expect(page.locator('text=Consultation booked!')).toBeVisible();
  });
});
```

### Day 5-6: Performance Optimization

#### 1. Performance Monitoring
```typescript
// apps/web/lib/performance.ts
export class PerformanceMonitor {
  private static marks: Map<string, number> = new Map();

  static mark(name: string) {
    if (typeof window !== 'undefined' && window.performance) {
      window.performance.mark(name);
      this.marks.set(name, performance.now());
    }
  }

  static measure(name: string, startMark: string, endMark?: string) {
    if (typeof window !== 'undefined' && window.performance) {
      try {
        window.performance.measure(name, startMark, endMark);
        const measure = window.performance.getEntriesByName(name, 'measure')[0];
        
        // Log to analytics
        if (window.gtag) {
          window.gtag('event', 'timing_complete', {
            name,
            value: Math.round(measure.duration),
            event_category: 'Performance',
          });
        }

        return measure.duration;
      } catch (error) {
        console.error('Performance measurement failed:', error);
      }
    }
    return null;
  }

  static reportWebVitals(metric: any) {
    if (window.gtag) {
      window.gtag('event', metric.name, {
        value: Math.round(metric.value),
        event_category: 'Web Vitals',
        event_label: metric.id,
        non_interaction: true,
      });
    }

    // Send to custom analytics endpoint
    fetch('/api/analytics/vitals', {
      method: 'POST',
      body: JSON.stringify(metric),
      headers: { 'Content-Type': 'application/json' },
    }).catch(() => {});
  }

  static async measureApiCall<T>(
    name: string,
    apiCall: () => Promise<T>
  ): Promise<T> {
    const start = performance.now();
    
    try {
      const result = await apiCall();
      const duration = performance.now() - start;
      
      this.logApiPerformance(name, duration, true);
      return result;
    } catch (error) {
      const duration = performance.now() - start;
      this.logApiPerformance(name, duration, false);
      throw error;
    }
  }

  private static logApiPerformance(
    endpoint: string,
    duration: number,
    success: boolean
  ) {
    if (window.gtag) {
      window.gtag('event', 'api_call', {
        endpoint,
        duration: Math.round(duration),
        success,
        event_category: 'API Performance',
      });
    }
  }
}
```

#### 2. Image Optimization Component
```typescript
// apps/web/components/optimized-image.tsx
'use client';

import { useState, useEffect } from 'react';
import Image from 'next/image';
import { cn } from '@/lib/utils';

interface OptimizedImageProps {
  src: string;
  alt: string;
  width?: number;
  height?: number;
  priority?: boolean;
  className?: string;
  objectFit?: 'cover' | 'contain' | 'fill';
  quality?: number;
  onLoad?: () => void;
  placeholder?: 'blur' | 'empty';
  blurDataURL?: string;
}

export function OptimizedImage({
  src,
  alt,
  width,
  height,
  priority = false,
  className,
  objectFit = 'cover',
  quality = 75,
  onLoad,
  placeholder = 'blur',
  blurDataURL,
}: OptimizedImageProps) {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(false);

  // Generate blur placeholder if not provided
  const defaultBlurDataURL = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ...';

  useEffect(() => {
    // Preload image for priority images
    if (priority && typeof window !== 'undefined') {
      const link = document.createElement('link');
      link.rel = 'preload';
      link.as = 'image';
      link.href = src;
      document.head.appendChild(link);
    }
  }, [src, priority]);

  return (
    <div className={cn('relative overflow-hidden', className)}>
      {isLoading && (
        <div className="absolute inset-0 bg-gray-200 dark:bg-gray-800 animate-pulse" />
      )}
      
      {error ? (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-100 dark:bg-gray-900">
          <Icons.image className="h-8 w-8 text-gray-400" />
        </div>
      ) : (
        <Image
          src={src}
          alt={alt}
          width={width}
          height={height}
          priority={priority}
          quality={quality}
          className={cn(
            'duration-700 ease-in-out',
            isLoading ? 'scale-110 blur-2xl' : 'scale-100 blur-0',
            className
          )}
          style={{ objectFit }}
          placeholder={placeholder}
          blurDataURL={blurDataURL || defaultBlurDataURL}
          onLoadingComplete={() => {
            setIsLoading(false);
            onLoad?.();
          }}
          onError={() => {
            setIsLoading(false);
            setError(true);
          }}
          sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw"
        />
      )}
    </div>
  );
}
```

### Day 7: Deployment

#### 1. Docker Production Configuration
```dockerfile
# Dockerfile
# Base image
FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Dependencies
FROM base AS deps
COPY package.json package-lock.json ./
COPY apps/*/package.json apps/*/
COPY packages/*/package.json packages/*/
COPY services/*/package.json services/*/
RUN npm ci --only=production

# Builder
FROM base AS builder
COPY package.json package-lock.json ./
COPY apps/*/package.json apps/*/
COPY packages/*/package.json packages/*/
COPY services/*/package.json services/*/
RUN npm ci

COPY . .
RUN npm run build

# Runner
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder /app/apps/web/.next/standalone ./
COPY --from=builder /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder /app/apps/web/public ./apps/web/public

USER nextjs

EXPOSE 3000

ENV PORT 3000

CMD ["node", "apps/web/server.js"]
```

#### 2. Kubernetes Deployment
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nutrition-platform-web
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nutrition-web
  template:
    metadata:
      labels:
        app: nutrition-web
    spec:
      containers:
      - name: web
        image: nutrition-platform/web:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: nutrition-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: nutrition-secrets
              key: redis-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: nutrition-web-service
  namespace: production
spec:
  selector:
    app: nutrition-web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 3000
  type: LoadBalancer
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: nutrition-web-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: nutrition-platform-web
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### 3. GitHub Actions Deployment
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]
  workflow_dispatch:

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests
        run: npm test
      
      - name: Run E2E tests
        run: npm run test:e2e

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=sha,prefix={{branch}}-
            type=raw,value=latest,enable={{is_default_branch}}
      
      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ap-south-1
      
      - name: Update kubeconfig
        run: |
          aws eks update-kubeconfig --name nutrition-cluster --region ap-south-1
      
      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/nutrition-platform-web \
            web=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
            -n production
          
          kubectl rollout status deployment/nutrition-platform-web -n production
          
      - name: Run smoke tests
        run: |
          npm run test:smoke
      
      - name: Notify deployment
        if: always()
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: 'Production deployment ${{ job.status }}'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

## Week 13: Post-Launch Monitoring & Optimization

### Day 1-2: Monitoring Setup

#### 1. Health Check Endpoints
```typescript
// apps/web/app/api/health/route.ts
import { NextResponse } from 'next/server';
import { prisma } from '@nutrition/database';
import { redisClient } from '@/lib/redis';

export async function GET() {
  const checks = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    checks: {
      database: 'checking',
      redis: 'checking',
      storage: 'checking',
    },
  };

  try {
    // Check database
    await prisma.$queryRaw`SELECT 1`;
    checks.checks.database = 'healthy';
  } catch (error) {
    checks.checks.database = 'unhealthy';
    checks.status = 'degraded';
  }

  try {
    // Check Redis
    await redisClient.ping();
    checks.checks.redis = 'healthy';
  } catch (error) {
    checks.checks.redis = 'unhealthy';
    checks.status = 'degraded';
  }

  try {
    // Check storage
    const response = await fetch(`${process.env.STORAGE_URL}/health`);
    checks.checks.storage = response.ok ? 'healthy' : 'unhealthy';
  } catch (error) {
    checks.checks.storage = 'unhealthy';
    checks.status = 'degraded';
  }

  return NextResponse.json(checks, {
    status: checks.status === 'ok' ? 200 : 503,
  });
}

// apps/web/app/api/ready/route.ts
export async function GET() {
  // Check if application is ready to receive traffic
  const ready = {
    ready: true,
    checks: {
      migrations: true,
      cache: true,
      config: true,
    },
  };

  // Verify critical services are initialized
  if (!process.env.DATABASE_URL) {
    ready.checks.config = false;
    ready.ready = false;
  }

  return NextResponse.json(ready, {
    status: ready.ready ? 200 : 503,
  });
}
```

#### 2. Monitoring Service
```typescript
// packages/monitoring/src/index.ts
import { Histogram, Counter, Gauge, register } from 'prom-client';

// Metrics
export const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.5, 1, 2, 5],
});

export const httpRequestTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
});

export const activeUsers = new Gauge({
  name: 'active_users',
  help: 'Number of active users',
});

export const databaseConnectionPool = new Gauge({
  name: 'database_connection_pool_size',
  help: 'Database connection pool metrics',
  labelNames: ['state'],
});

export const businessMetrics = {
  consultationsBooked: new Counter({
    name: 'consultations_booked_total',
    help: 'Total number of consultations booked',
    labelNames: ['program_type', 'nutritionist'],
  }),

  paymentsProcessed: new Counter({
    name: 'payments_processed_total',
    help: 'Total payments processed',
    labelNames: ['status', 'gateway'],
  }),

  revenueTotal: new Gauge({
    name: 'revenue_total',
    help: 'Total revenue',
    labelNames: ['currency'],
  }),

  programEnrollments: new Counter({
    name: 'program_enrollments_total',
    help: 'Total program enrollments',
    labelNames: ['program_type'],
  }),
};

// Middleware
export function metricsMiddleware(req: any, res: any, next: any) {
  const start = Date.now();

  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const route = req.route?.path || req.path;
    const labels = {
      method: req.method,
      route,
      status_code: res.statusCode,
    };

    httpRequestDuration.observe(labels, duration);
    httpRequestTotal.inc(labels);
  });

  next();
}

// Metrics endpoint
export async function getMetrics() {
  // Update business metrics
  const stats = await getBusinessStats();
  activeUsers.set(stats.activeUsers);
  businessMetrics.revenueTotal.set({ currency: 'INR' }, stats.totalRevenue);

  return register.metrics();
}

async function getBusinessStats() {
  // Fetch from database
  return {
    activeUsers: 0,
    totalRevenue: 0,
  };
}
```

### Day 3-4: Error Tracking & Logging

#### 1. Error Tracking Setup
```typescript
// packages/error-tracking/src/index.ts
import * as Sentry from '@sentry/node';
import { ProfilingIntegration } from '@sentry/profiling-node';

export function initializeErrorTracking() {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV,
    integrations: [
      new ProfilingIntegration(),
    ],
    tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
    profilesSampleRate: 0.1,
    beforeSend(event, hint) {
      // Filter out sensitive data
      if (event.request?.cookies) {
        delete event.request.cookies;
      }
      
      // Don't send events in development
      if (process.env.NODE_ENV === 'development') {
        console.error('Sentry Event:', event, hint);
        return null;
      }
      
      return event;
    },
  });
}

export function captureError(error: Error, context?: any) {
  console.error('Error:', error);
  
  if (process.env.NODE_ENV === 'production') {
    Sentry.captureException(error, {
      extra: context,
    });
  }
}

export function captureMessage(message: string, level: Sentry.SeverityLevel = 'info') {
  if (process.env.NODE_ENV === 'production') {
    Sentry.captureMessage(message, level);
  }
}

export function setUserContext(user: any) {
  Sentry.setUser({
    id: user.id,
    email: user.email,
    username: user.username,
  });
}

export function addBreadcrumb(breadcrumb: any) {
  Sentry.addBreadcrumb(breadcrumb);
}

// Error boundary for React
export function ErrorBoundary({ children }: { children: React.ReactNode }) {
  return (
    <Sentry.ErrorBoundary
      fallback={({ error, resetError }) => (
        <div className="flex min-h-screen flex-col items-center justify-center">
          <h1 className="text-2xl font-bold mb-4">Something went wrong</h1>
          <p className="text-gray-600 mb-4">We've been notified about this issue.</p>
          <button
            onClick={resetError}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            Try again
          </button>
        </div>
      )}
      showDialog
    >
      {children}
    </Sentry.ErrorBoundary>
  );
}
```

#### 2. Structured Logging
```typescript
// packages/logger/src/index.ts
import winston from 'winston';
import { ElasticsearchTransport } from 'winston-elasticsearch';

const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(colors);

// Formatters
const devFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: ${info.message}`
  )
);

const prodFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Transports
const transports: winston.transport[] = [
  new winston.transports.Console({
    format: process.env.NODE_ENV === 'production' ? prodFormat : devFormat,
  }),
];

if (process.env.NODE_ENV === 'production') {
  // Add Elasticsearch transport for production
  transports.push(
    new ElasticsearchTransport({
      index: 'nutrition-platform-logs',
      clientOpts: {
        node: process.env.ELASTICSEARCH_URL,
        auth: {
          username: process.env.ELASTICSEARCH_USER,
          password: process.env.ELASTICSEARCH_PASS,
        },
      },
    })
  );

  // Add file transport
  transports.push(
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
    })
  );
}

// Create logger
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels: logLevels,
  format: prodFormat,
  transports,
  exceptionHandlers: [
    new winston.transports.File({ filename: 'logs/exceptions.log' }),
  ],
  rejectionHandlers: [
    new winston.transports.File({ filename: 'logs/rejections.log' }),
  ],
});

// HTTP request logger middleware
export const httpLogger = winston.createLogger({
  level: 'http',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf((info) => {
      const { timestamp, level, message, ...meta } = info;
      return JSON.stringify({
        timestamp,
        level,
        message,
        ...meta,
      });
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: 'logs/http.log',
      maxsize: 10485760,
      maxFiles: 5,
    }),
  ],
});

// Utility functions
export function logError(error: Error, context?: any) {
  logger.error({
    message: error.message,
    stack: error.stack,
    context,
  });
}

export function logInfo(message: string, meta?: any) {
  logger.info(message, meta);
}

export function logWarning(message: string, meta?: any) {
  logger.warn(message, meta);
}

export function logDebug(message: string, meta?: any) {
  logger.debug(message, meta);
}

// Request logger middleware
export function requestLogger(req: any, res: any, next: any) {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    
    httpLogger.http({
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: req.user?.id,
    });
  });

  next();
}
```

### Day 5-6: Performance Monitoring

#### 1. Performance Monitoring Dashboard
```typescript
// apps/web/app/admin/performance/page.tsx
'use client';

import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { MetricCard } from '@/components/performance/metric-card';
import { ResponseTimeChart } from '@/components/performance/response-time-chart';
import { ErrorRateChart } from '@/components/performance/error-rate-chart';
import { ThroughputChart } from '@/components/performance/throughput-chart';
import { DatabasePerformance } from '@/components/performance/database-performance';
import { api } from '@/lib/api';

export default function PerformancePage() {
  const { data: metrics } = useQuery({
    queryKey: ['performance-metrics'],
    queryFn: async () => {
      const response = await api.get('/admin/performance/metrics');
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: vitals } = useQuery({
    queryKey: ['web-vitals'],
    queryFn: async () => {
      const response = await api.get('/admin/performance/vitals');
      return response.data;
    },
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Performance Monitoring</h1>
        <p className="text-muted-foreground">
          Real-time application performance metrics
        </p>
      </div>

      {/* Key Performance Indicators */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Avg Response Time"
          value={`${metrics?.avgResponseTime || 0}ms`}
          trend={metrics?.responseTimeTrend}
          target={200}
          unit="ms"
        />
        
        <MetricCard
          title="Error Rate"
          value={`${metrics?.errorRate || 0}%`}
          trend={metrics?.errorRateTrend}
          target={1}
          unit="%"
          inverse
        />
        
        <MetricCard
          title="Throughput"
          value={`${metrics?.throughput || 0} req/s`}
          trend={metrics?.throughputTrend}
          target={1000}
          unit="req/s"
        />
        
        <MetricCard
          title="Uptime"
          value={`${metrics?.uptime || 0}%`}
          trend={0}
          target={99.9}
          unit="%"
        />
      </div>

      {/* Web Vitals */}
      <Card>
        <CardHeader>
          <CardTitle>Core Web Vitals</CardTitle>
          <CardDescription>
            User experience metrics from real users
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2">
              <p className="text-sm font-medium">LCP (Largest Contentful Paint)</p>
              <p className="text-2xl font-bold">{vitals?.lcp || 0}s</p>
              <p className="text-xs text-muted-foreground">
                Target: &lt; 2.5s (Good)
              </p>
              <Progress 
                value={(2.5 - (vitals?.lcp || 0)) / 2.5 * 100} 
                className="h-2"
              />
            </div>
            
            <div className="space-y-2">
              <p className="text-sm font-medium">FID (First Input Delay)</p>
              <p className="text-2xl font-bold">{vitals?.fid || 0}ms</p>
              <p className="text-xs text-muted-foreground">
                Target: &lt; 100ms (Good)
              </p>
              <Progress 
                value={(100 - (vitals?.fid || 0)) / 100 * 100} 
                className="h-2"
              />
            </div>
            
            <div className="space-y-2">
              <p className="text-sm font-medium">CLS (Cumulative Layout Shift)</p>
              <p className="text-2xl font-bold">{vitals?.cls || 0}</p>
              <p className="text-xs text-muted-foreground">
                Target: &lt; 0.1 (Good)
              </p>
              <Progress 
                value={(0.1 - (vitals?.cls || 0)) / 0.1 * 100} 
                className="h-2"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detailed Metrics */}
      <Tabs defaultValue="response-time" className="space-y-4">
        <TabsList>
          <TabsTrigger value="response-time">Response Time</TabsTrigger>
          <TabsTrigger value="error-rate">Error Rate</TabsTrigger>
          <TabsTrigger value="throughput">Throughput</TabsTrigger>
          <TabsTrigger value="database">Database</TabsTrigger>
        </TabsList>

        <TabsContent value="response-time">
          <ResponseTimeChart />
        </TabsContent>

        <TabsContent value="error-rate">
          <ErrorRateChart />
        </TabsContent>

        <TabsContent value="throughput">
          <ThroughputChart />
        </TabsContent>

        <TabsContent value="database">
          <DatabasePerformance />
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

### Day 7: Production Checklist

#### 1. Security Checklist
```typescript
// scripts/security-audit.ts
import { exec } from 'child_process';
import { promisify } from 'util';
import chalk from 'chalk';

const execAsync = promisify(exec);

interface SecurityCheck {
  name: string;
  command: string;
  validator?: (output: string) => boolean;
}

const securityChecks: SecurityCheck[] = [
  {
    name: 'Dependency vulnerabilities',
    command: 'npm audit --json',
    validator: (output) => {
      const audit = JSON.parse(output);
      return audit.metadata.vulnerabilities.high === 0 && 
             audit.metadata.vulnerabilities.critical === 0;
    },
  },
  {
    name: 'Environment variables',
    command: 'node -e "console.log(JSON.stringify(Object.keys(process.env).filter(k => k.includes(\'SECRET\'))))"',
    validator: (output) => {
      const secrets = JSON.parse(output);
      return secrets.every((key: string) => process.env[key] !== 'changeme');
    },
  },
  {
    name: 'SSL/TLS configuration',
    command: 'openssl s_client -connect localhost:443 -servername localhost < /dev/null 2>/dev/null | openssl x509 -noout -dates',
    validator: (output) => {
      return output.includes('notAfter=');
    },
  },
  {
    name: 'Security headers',
    command: 'curl -I https://localhost',
    validator: (output) => {
      const requiredHeaders = [
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Content-Security-Policy',
      ];
      return requiredHeaders.every(header => output.includes(header));
    },
  },
];

async function runSecurityAudit() {
  console.log(chalk.blue('🔒 Running Security Audit...\n'));

  const results = [];

  for (const check of securityChecks) {
    try {
      const { stdout } = await execAsync(check.command);
      const passed = check.validator ? check.validator(stdout) : true;
      
      results.push({
        name: check.name,
        passed,
        output: stdout,
      });

      if (passed) {
        console.log(chalk.green(`✅ ${check.name}`));
      } else {
        console.log(chalk.red(`❌ ${check.name}`));
        console.log(chalk.gray(stdout));
      }
    } catch (error) {
      console.log(chalk.red(`❌ ${check.name} - Error running check`));
      results.push({
        name: check.name,
        passed: false,
        error: error.message,
      });
    }
  }

  const failedChecks = results.filter(r => !r.passed);
  
  console.log('\n' + chalk.blue('Summary:'));
  console.log(chalk.green(`Passed: ${results.length - failedChecks.length}`));
  console.log(chalk.red(`Failed: ${failedChecks.length}`));

  if (failedChecks.length > 0) {
    console.log(chalk.red('\n⚠️  Security issues detected. Please fix before deploying.'));
    process.exit(1);
  } else {
    console.log(chalk.green('\n✅ All security checks passed!'));
  }
}

runSecurityAudit();
```

#### 2. Pre-deployment Checklist
```markdown
# Production Deployment Checklist

## Security
- [ ] All dependencies updated and audited
- [ ] Environment variables properly configured
- [ ] Secrets stored in secure vault (not in code)
- [ ] SSL certificates valid and auto-renewing
- [ ] Security headers configured
- [ ] CORS properly configured
- [ ] Rate limiting enabled
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention verified
- [ ] XSS prevention implemented
- [ ] CSRF protection enabled

## Performance
- [ ] Database indexes created
- [ ] Query optimization completed
- [ ] Redis caching implemented
- [ ] CDN configured for static assets
- [ ] Image optimization enabled
- [ ] Code splitting implemented
- [ ] Bundle size optimized
- [ ] Lazy loading implemented
- [ ] Service worker for offline support

## Monitoring
- [ ] Error tracking configured (Sentry)
- [ ] Performance monitoring enabled
- [ ] Uptime monitoring configured
- [ ] Log aggregation setup
- [ ] Alerts configured for critical events
- [ ] Custom metrics dashboard created
- [ ] Database monitoring enabled
- [ ] Resource usage alerts

## Backup & Recovery
- [ ] Database backup automated
- [ ] Backup restoration tested
- [ ] Disaster recovery plan documented
- [ ] Data retention policies implemented
- [ ] Point-in-time recovery tested

## Compliance
- [ ] GDPR compliance verified
- [ ] Privacy policy updated
- [ ] Terms of service updated
- [ ] Cookie consent implemented
- [ ] Data deletion process tested
- [ ] Audit logging enabled

## Testing
- [ ] Unit tests passing (>80% coverage)
- [ ] Integration tests passing
- [ ] E2E tests passing
- [ ] Load testing completed
- [ ] Security testing completed
- [ ] Accessibility testing passed
- [ ] Cross-browser testing done
- [ ] Mobile testing completed

## Documentation
- [ ] API documentation complete
- [ ] Deployment guide updated
- [ ] Runbook created
- [ ] Architecture diagrams updated
- [ ] Database schema documented
- [ ] Third-party services documented

## Infrastructure
- [ ] Auto-scaling configured
- [ ] Load balancer health checks
- [ ] Database connection pooling
- [ ] Redis persistence configured
- [ ] Kubernetes resources defined
- [ ] Secrets management setup
- [ ] Network policies configured
- [ ] Firewall rules reviewed

## Final Steps
- [ ] Staging environment tested
- [ ] Rollback plan prepared
- [ ] Team notified of deployment
- [ ] Maintenance window scheduled
- [ ] Customer communication sent
- [ ] Post-deployment verification plan
```

## Conclusion

This comprehensive 12-week development plan provides a complete roadmap for building a production-ready nutrition platform. The implementation covers:

1. **Robust Architecture**: Microservices-based design with proper separation of concerns
2. **Security First**: Multiple layers of security including 2FA, encryption, and proper authentication
3. **Scalability**: Designed to handle growth with proper caching, queuing, and database optimization
4. **User Experience**: Modern, responsive UI with real-time features and progressive enhancement
5. **Business Features**: Complete implementation of all required features from the brief
6. **Monitoring & Analytics**: Comprehensive tracking and monitoring for business intelligence
7. **Testing**: Thorough testing strategy ensuring reliability
8. **Deployment**: Production-ready deployment with proper CI/CD

The platform is built with:
- **99% Open Source Technologies**: Minimizing costs while maintaining quality
- **Indian Market Focus**: Payment gateways, WhatsApp integration, and local compliance
- **Modern Tech Stack**: Next.js, Node.js, PostgreSQL, Redis, and more
- **Best Practices**: Following industry standards for security, performance, and maintainability

This implementation provides a solid foundation that can be extended and scaled as the business grows, while keeping initial costs manageable through the strategic use of open-source technologies.# Comprehensive Weekly Implementation Guide - Functional Nutrition Platform

## Week 1: Project Foundation & Infrastructure Setup

### Day 1-2: Repository and Monorepo Setup

#### 1. Initialize Monorepo Structure
```bash
# Create project directory
mkdir nutrition-platform && cd nutrition-platform

# Initialize git repository
git init

# Create monorepo structure
mkdir -p apps/{web,api,admin,mobile-pwa}
mkdir -p packages/{ui,utils,types,config,database}
mkdir -p services/{auth,user,consultation,payment,content,quiz,notification,analytics}
mkdir -p infrastructure/{docker,kubernetes,terraform,scripts}
mkdir -p docs/{api,architecture,deployment}

# Initialize npm workspaces
npm init -y
```

#### 2. Setup package.json for Workspaces
```json
{
  "name": "nutrition-platform",
  "private": true,
  "workspaces": [
    "apps/*",
    "packages/*",
    "services/*"
  ],
  "scripts": {
    "dev": "turbo run dev",
    "build": "turbo run build",
    "test": "turbo run test",
    "lint": "turbo run lint",
    "format": "prettier --write \"**/*.{ts,tsx,js,jsx,json,md}\"",
    "prepare": "husky install"
  },
  "devDependencies": {
    "turbo": "^1.11.0",
    "@types/node": "^20.10.0",
    "typescript": "^5.3.0",
    "prettier": "^3.1.0",
    "eslint": "^8.55.0",
    "husky": "^8.0.3",
    "lint-staged": "^15.2.0"
  }
}
```

#### 3. Setup Turborepo Configuration
```json
// turbo.json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": [".next/**", "dist/**"]
    },
    "dev": {
      "cache": false,
      "persistent": true
    },
    "test": {
      "dependsOn": ["build"],
      "inputs": ["src/**", "tests/**"]
    },
    "lint": {},
    "type-check": {}
  }
}
```

#### 4. Setup TypeScript Configuration
```json
// tsconfig.base.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "jsx": "preserve",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "moduleResolution": "node",
    "baseUrl": ".",
    "paths": {
      "@nutrition/*": ["packages/*/src"]
    }
  },
  "exclude": ["node_modules", "dist", ".next", "coverage"]
}
```

### Day 3-4: Docker Environment Setup

#### 1. Create Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: nutrition_postgres
    environment:
      POSTGRES_USER: nutrition_user
      POSTGRES_PASSWORD: nutrition_password
      POSTGRES_DB: nutrition_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./infrastructure/docker/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nutrition_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: nutrition_redis
    command: redis-server --requirepass nutrition_redis_password
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    container_name: nutrition_minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: nutrition_minio_user
      MINIO_ROOT_PASSWORD: nutrition_minio_password
    volumes:
      - minio_data:/data
    ports:
      - "9000:9000"
      - "9001:9001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 20s
      retries: 3

  meilisearch:
    image: getmeili/meilisearch:latest
    container_name: nutrition_meilisearch
    environment:
      MEILI_MASTER_KEY: nutrition_meilisearch_key
      MEILI_ENV: development
    volumes:
      - meilisearch_data:/meili_data
    ports:
      - "7700:7700"

  mailhog:
    image: mailhog/mailhog:latest
    container_name: nutrition_mailhog
    ports:
      - "1025:1025"
      - "8025:8025"

volumes:
  postgres_data:
  redis_data:
  minio_data:
  meilisearch_data:
```

#### 2. Create Development Dockerfile
```dockerfile
# Dockerfile.dev
FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat
RUN apk update
WORKDIR /app

# Install dependencies
FROM base AS deps
COPY package.json package-lock.json ./
COPY apps/*/package.json apps/*/
COPY packages/*/package.json packages/*/
COPY services/*/package.json services/*/
RUN npm ci

# Development
FROM base AS dev
COPY --from=deps /app/node_modules ./node_modules
COPY . .
EXPOSE 3000 4000
CMD ["npm", "run", "dev"]
```

### Day 5: CI/CD Pipeline Setup

#### 1. GitHub Actions Configuration
```yaml
# .github/workflows/main.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  NODE_VERSION: '20'
  PNPM_VERSION: '8'

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Run ESLint
        run: npm run lint
      - name: Run Type Check
        run: npm run type-check

  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test_password
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Run unit tests
        run: npm run test:unit
      - name: Run integration tests
        run: npm run test:integration
        env:
          DATABASE_URL: postgresql://postgres:test_password@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379

  build:
    needs: [lint, test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
      - name: Install dependencies
        run: npm ci
      - name: Build applications
        run: npm run build
      - name: Build Docker images
        run: |
          docker build -f Dockerfile.api -t nutrition-api:${{ github.sha }} .
          docker build -f Dockerfile.web -t nutrition-web:${{ github.sha }} .
      - name: Push to registry
        if: github.ref == 'refs/heads/main'
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push nutrition-api:${{ github.sha }}
          docker push nutrition-web:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Deploy to staging
        run: |
          # Deploy to Kubernetes or other platform
          echo "Deploying to staging..."
```

#### 2. Environment Configuration
```bash
# .env.example
# Application
NODE_ENV=development
PORT=4000
CLIENT_URL=http://localhost:3000
API_URL=http://localhost:4000

# Database
DATABASE_URL=postgresql://nutrition_user:nutrition_password@localhost:5432/nutrition_db
REDIS_URL=redis://:nutrition_redis_password@localhost:6379

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# 2FA
TWO_FA_APP_NAME=NutritionPlatform

# File Storage
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_ACCESS_KEY=nutrition_minio_user
MINIO_SECRET_KEY=nutrition_minio_password
MINIO_BUCKET=nutrition-uploads

# Search
MEILISEARCH_HOST=http://localhost:7700
MEILISEARCH_KEY=nutrition_meilisearch_key

# Email (Development)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=
SMTP_PASS=
EMAIL_FROM=noreply@nutritionplatform.com

# Payment Gateway
RAZORPAY_KEY_ID=your_razorpay_key
RAZORPAY_KEY_SECRET=your_razorpay_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# WhatsApp
WHATSAPP_API_URL=https://api.whatsapp.com/v1
WHATSAPP_TOKEN=your_whatsapp_token
WHATSAPP_PHONE_ID=your_phone_id

# SMS
SMS_PROVIDER=msg91
MSG91_AUTH_KEY=your_msg91_key
MSG91_SENDER_ID=NUTRIT

# Analytics
GA_TRACKING_ID=G-XXXXXXXXXX
HOTJAR_SITE_ID=1234567

# PayloadCMS
PAYLOAD_SECRET=your-payload-secret
PAYLOAD_CONFIG_PATH=src/payload.config.ts
```

### Day 6-7: Database Schema Implementation

#### 1. Prisma Setup and Schema
```bash
# Install Prisma
cd packages/database
npm init -y
npm install prisma @prisma/client
npm install -D @types/node typescript

# Initialize Prisma
npx prisma init
```

```prisma
// packages/database/prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// Enums
enum UserRole {
  USER
  NUTRITIONIST
  ADMIN
}

enum Gender {
  MALE
  FEMALE
  OTHER
  PREFER_NOT_TO_SAY
}

enum ConsultationStatus {
  SCHEDULED
  IN_PROGRESS
  COMPLETED
  CANCELLED
  NO_SHOW
}

enum PaymentStatus {
  PENDING
  PROCESSING
  SUCCESS
  FAILED
  REFUNDED
}

enum ProgramType {
  GUT_HEALTH
  METABOLIC_RESET
  PCOS_RESTORE
  DIABETES_CARE
  DETOX_HORMONE
  CUSTOM
}

enum QuizType {
  SYMPTOM
  GUT_HEALTH
  STRESS
  NUTRITION
  LIFESTYLE
}

// Models
model User {
  id              String    @id @default(uuid())
  email           String    @unique
  phone           String?   @unique
  passwordHash    String    @map("password_hash")
  role            UserRole  @default(USER)
  emailVerified   Boolean   @default(false) @map("email_verified")
  phoneVerified   Boolean   @default(false) @map("phone_verified")
  twoFASecret     String?   @map("two_fa_secret")
  twoFAEnabled    Boolean   @default(false) @map("two_fa_enabled")
  lastLoginAt     DateTime? @map("last_login_at")
  createdAt       DateTime  @default(now()) @map("created_at")
  updatedAt       DateTime  @updatedAt @map("updated_at")

  // Relations
  profile              UserProfile?
  consultations        Consultation[]
  payments            Payment[]
  quizResults         QuizResult[]
  journeys            UserJourney[]
  documents           Document[]
  notifications       Notification[]
  refreshTokens       RefreshToken[]
  nutritionistProfile NutritionistProfile?
  consultationsAsNutritionist Consultation[] @relation("NutritionistConsultations")

  @@map("users")
  @@index([email])
  @@index([phone])
}

model UserProfile {
  id            String    @id @default(uuid())
  userId        String    @unique @map("user_id")
  firstName     String    @map("first_name")
  lastName      String    @map("last_name")
  dateOfBirth   DateTime? @map("date_of_birth")
  gender        Gender?
  avatar        String?
  bio           String?
  height        Float?    // in cm
  weight        Float?    // in kg
  bloodGroup    String?   @map("blood_group")
  allergies     String[]
  medications   String[]
  medicalHistory Json?    @map("medical_history")
  preferences   Json?
  timezone      String    @default("Asia/Kolkata")
  language      String    @default("en")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("user_profiles")
}

model NutritionistProfile {
  id                String   @id @default(uuid())
  userId            String   @unique @map("user_id")
  registrationNumber String?  @map("registration_number")
  qualifications    String[]
  specializations   String[]
  experience        Int      // in years
  aboutMe           String?  @map("about_me")
  consultationFee   Float    @map("consultation_fee")
  languages         String[]
  availability      Json?    // Weekly availability schedule
  rating            Float    @default(0)
  totalReviews      Int      @default(0) @map("total_reviews")
  isActive          Boolean  @default(true) @map("is_active")
  createdAt         DateTime @default(now()) @map("created_at")
  updatedAt         DateTime @updatedAt @map("updated_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("nutritionist_profiles")
}

model Program {
  id              String      @id @default(uuid())
  name            String
  slug            String      @unique
  type            ProgramType
  description     String
  shortDescription String?    @map("short_description")
  duration        Int         // in days
  price           Float
  discountedPrice Float?      @map("discounted_price")
  currency        String      @default("INR")
  features        String[]
  includes        Json?       // Detailed list of what's included
  outcomes        String[]    // Expected outcomes
  whoIsItFor      String[]    @map("who_is_it_for")
  image           String?
  isActive        Boolean     @default(true) @map("is_active")
  isFeatured      Boolean     @default(false) @map("is_featured")
  order           Int         @default(0)
  metadata        Json?
  createdAt       DateTime    @default(now()) @map("created_at")
  updatedAt       DateTime    @updatedAt @map("updated_at")

  // Relations
  consultations Consultation[]
  journeys      UserJourney[]
  reviews       ProgramReview[]

  @@map("programs")
  @@index([slug])
  @@index([type])
}

model Consultation {
  id               String             @id @default(uuid())
  userId           String             @map("user_id")
  nutritionistId   String             @map("nutritionist_id")
  programId        String?            @map("program_id")
  scheduledAt      DateTime           @map("scheduled_at")
  duration         Int                // in minutes
  status           ConsultationStatus @default(SCHEDULED)
  meetingLink      String?            @map("meeting_link")
  meetingId        String?            @map("meeting_id")
  notes            String?
  internalNotes    String?            @map("internal_notes")
  recordingUrl     String?            @map("recording_url")
  prescription     Json?              // Structured prescription data
  followUpDate     DateTime?          @map("follow_up_date")
  completedAt      DateTime?          @map("completed_at")
  cancelledAt      DateTime?          @map("cancelled_at")
  cancellationReason String?          @map("cancellation_reason")
  createdAt        DateTime           @default(now()) @map("created_at")
  updatedAt        DateTime           @updatedAt @map("updated_at")

  // Relations
  user         User     @relation(fields: [userId], references: [id])
  nutritionist User     @relation("NutritionistConsultations", fields: [nutritionistId], references: [id])
  program      Program? @relation(fields: [programId], references: [id])
  payment      Payment?
  reminders    ConsultationReminder[]

  @@map("consultations")
  @@index([userId])
  @@index([nutritionistId])
  @@index([scheduledAt])
  @@index([status])
}

model ConsultationReminder {
  id              String       @id @default(uuid())
  consultationId  String       @map("consultation_id")
  type            String       // email, sms, whatsapp
  scheduledAt     DateTime     @map("scheduled_at")
  sentAt          DateTime?    @map("sent_at")
  status          String       // pending, sent, failed
  createdAt       DateTime     @default(now()) @map("created_at")

  // Relations
  consultation Consultation @relation(fields: [consultationId], references: [id], onDelete: Cascade)

  @@map("consultation_reminders")
  @@index([consultationId])
  @@index([scheduledAt])
}

model Payment {
  id                  String        @id @default(uuid())
  userId              String        @map("user_id")
  consultationId      String?       @unique @map("consultation_id")
  journeyId           String?       @map("journey_id")
  amount              Float
  currency            String        @default("INR")
  status              PaymentStatus @default(PENDING)
  gateway             String        // razorpay, cashfree
  gatewayOrderId      String?       @map("gateway_order_id")
  gatewayPaymentId    String?       @map("gateway_payment_id")
  gatewaySignature    String?       @map("gateway_signature")
  paymentMethod       String?       @map("payment_method")
  refundId            String?       @map("refund_id")
  refundAmount        Float?        @map("refund_amount")
  refundedAt          DateTime?     @map("refunded_at")
  metadata            Json?
  invoiceNumber       String?       @unique @map("invoice_number")
  invoiceUrl          String?       @map("invoice_url")
  receiptUrl          String?       @map("receipt_url")
  failureReason       String?       @map("failure_reason")
  createdAt           DateTime      @default(now()) @map("created_at")
  updatedAt           DateTime      @updatedAt @map("updated_at")

  // Relations
  user         User          @relation(fields: [userId], references: [id])
  consultation Consultation? @relation(fields: [consultationId], references: [id])
  journey      UserJourney?  @relation(fields: [journeyId], references: [id])

  @@map("payments")
  @@index([userId])
  @@index([status])
  @@index([gatewayOrderId])
  @@index([invoiceNumber])
}

model UserJourney {
  id            String    @id @default(uuid())
  userId        String    @map("user_id")
  programId     String    @map("program_id")
  startDate     DateTime  @map("start_date")
  endDate       DateTime? @map("end_date")
  status        String    @default("ACTIVE") // ACTIVE, PAUSED, COMPLETED, CANCELLED
  progress      Json?     // Milestone tracking
  measurements  Json?     // Weight, BMI, other health metrics over time
  mealPlans     Json?     @map("meal_plans")
  supplements   Json?
  notes         String?
  completedAt   DateTime? @map("completed_at")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  // Relations
  user         User          @relation(fields: [userId], references: [id])
  program      Program       @relation(fields: [programId], references: [id])
  payments     Payment[]
  checkIns     JourneyCheckIn[]
  mealEntries  MealEntry[]

  @@map("user_journeys")
  @@index([userId])
  @@index([programId])
  @@index([status])
}

model JourneyCheckIn {
  id          String      @id @default(uuid())
  journeyId   String      @map("journey_id")
  date        DateTime
  weight      Float?
  energy      Int?        // 1-10 scale
  mood        Int?        // 1-10 scale
  sleep       Float?      // hours
  exercise    Int?        // minutes
  water       Float?      // liters
  symptoms    String[]
  notes       String?
  photos      String[]    // URLs
  createdAt   DateTime    @default(now()) @map("created_at")

  // Relations
  journey UserJourney @relation(fields: [journeyId], references: [id], onDelete: Cascade)

  @@map("journey_check_ins")
  @@index([journeyId])
  @@index([date])
}

model MealEntry {
  id          String      @id @default(uuid())
  journeyId   String      @map("journey_id")
  date        DateTime
  mealType    String      @map("meal_type") // breakfast, lunch, dinner, snack
  foods       Json        // Array of food items with quantities
  calories    Float?
  protein     Float?      // in grams
  carbs       Float?      // in grams
  fat         Float?      // in grams
  fiber       Float?      // in grams
  notes       String?
  photo       String?
  createdAt   DateTime    @default(now()) @map("created_at")

  // Relations
  journey UserJourney @relation(fields: [journeyId], references: [id], onDelete: Cascade)

  @@map("meal_entries")
  @@index([journeyId])
  @@index([date])
}

model Quiz {
  id          String      @id @default(uuid())
  type        QuizType
  title       String
  description String?
  questions   Json        // Array of questions with options
  scoring     Json        // Scoring logic
  isActive    Boolean     @default(true) @map("is_active")
  createdAt   DateTime    @default(now()) @map("created_at")
  updatedAt   DateTime    @updatedAt @map("updated_at")

  // Relations
  results QuizResult[]

  @@map("quizzes")
  @@index([type])
}

model QuizResult {
  id              String   @id @default(uuid())
  userId          String?  @map("user_id")
  quizId          String   @map("quiz_id")
  quizType        QuizType @map("quiz_type")
  responses       Json     // User's answers
  score           Int?
  analysis        Json?    // Detailed analysis
  recommendations Json?    // Program/action recommendations
  ipAddress       String?  @map("ip_address")
  userAgent       String?  @map("user_agent")
  completedAt     DateTime @default(now()) @map("completed_at")

  // Relations
  user User? @relation(fields: [userId], references: [id])
  quiz Quiz  @relation(fields: [quizId], references: [id])

  @@map("quiz_results")
  @@index([userId])
  @@index([quizId])
  @@index([quizType])
}

model BlogPost {
  id            String    @id @default(uuid())
  title         String
  slug          String    @unique
  excerpt       String?
  content       String    @db.Text
  featuredImage String?   @map("featured_image")
  author        String
  category      String
  tags          String[]
  readTime      Int?      @map("read_time") // in minutes
  isPublished   Boolean   @default(false) @map("is_published")
  publishedAt   DateTime? @map("published_at")
  seoTitle      String?   @map("seo_title")
  seoDescription String?  @map("seo_description")
  seoKeywords   String[]  @map("seo_keywords")
  viewCount     Int       @default(0) @map("view_count")
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")

  @@map("blog_posts")
  @@index([slug])
  @@index([category])
  @@index([isPublished])
}

model Resource {
  id            String   @id @default(uuid())
  title         String
  description   String?
  type          String   // pdf, video, calculator, tracker
  category      String
  fileUrl       String?  @map("file_url")
  thumbnailUrl  String?  @map("thumbnail_url")
  isPublic      Boolean  @default(true) @map("is_public")
  requiresAuth  Boolean  @default(false) @map("requires_auth")
  downloadCount Int      @default(0) @map("download_count")
  tags          String[]
  metadata      Json?
  createdAt     DateTime @default(now()) @map("created_at")
  updatedAt     DateTime @updatedAt @map("updated_at")

  @@map("resources")
  @@index([type])
  @@index([category])
}

model Document {
  id           String   @id @default(uuid())
  userId       String   @map("user_id")
  type         String   // medical_report, prescription, meal_plan, etc
  title        String
  description  String?
  fileUrl      String   @map("file_url")
  fileSize     Int      @map("file_size") // in bytes
  mimeType     String   @map("mime_type")
  isArchived   Boolean  @default(false) @map("is_archived")
  metadata     Json?
  uploadedAt   DateTime @default(now()) @map("uploaded_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("documents")
  @@index([userId])
  @@index([type])
}

model Notification {
  id         String    @id @default(uuid())
  userId     String    @map("user_id")
  type       String    // email, sms, whatsapp, in-app
  category   String    // consultation, payment, journey, system
  title      String
  content    String
  data       Json?     // Additional data for the notification
  status     String    @default("PENDING") // PENDING, SENT, FAILED
  readAt     DateTime? @map("read_at")
  sentAt     DateTime? @map("sent_at")
  error      String?
  createdAt  DateTime  @default(now()) @map("created_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("notifications")
  @@index([userId])
  @@index([status])
  @@index([type])
}

model RefreshToken {
  id          String   @id @default(uuid())
  userId      String   @map("user_id")
  token       String   @unique
  expiresAt   DateTime @map("expires_at")
  createdAt   DateTime @default(now()) @map("created_at")

  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("refresh_tokens")
  @@index([token])
  @@index([userId])
}

model ProgramReview {
  id         String   @id @default(uuid())
  programId  String   @map("program_id")
  userId     String   @map("user_id")
  rating     Int      // 1-5
  title      String?
  comment    String?
  isVerified Boolean  @default(false) @map("is_verified")
  createdAt  DateTime @default(now()) @map("created_at")
  updatedAt  DateTime @updatedAt @map("updated_at")

  // Relations
  program Program @relation(fields: [programId], references: [id])

  @@map("program_reviews")
  @@unique([programId, userId])
  @@index([programId])
}

model AuditLog {
  id         String   @id @default(uuid())
  userId     String?  @map("user_id")
  action     String   // CREATE, UPDATE, DELETE, LOGIN, etc
  entity     String   // user, consultation, payment, etc
  entityId   String?  @map("entity_id")
  changes    Json?    // Before and after values
  ipAddress  String?  @map("ip_address")
  userAgent  String?  @map("user_agent")
  createdAt  DateTime @default(now()) @map("created_at")

  @@map("audit_logs")
  @@index([userId])
  @@index([entity])
  @@index([action])
  @@index([createdAt])
}
```

#### 2. Database Initialization Script
```sql
-- infrastructure/docker/postgres/init.sql
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create indexes for text search
CREATE INDEX idx_blog_posts_title_trgm ON blog_posts USING gin (title gin_trgm_ops);
CREATE INDEX idx_blog_posts_content_trgm ON blog_posts USING gin (content gin_trgm_ops);
CREATE INDEX idx_resources_title_trgm ON resources USING gin (title gin_trgm_ops);

-- Create functions for updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_profiles_updated_at BEFORE UPDATE ON user_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add more triggers for other tables...
```

## Week 2: Core Services & Authentication

### Day 1-2: Authentication Service Implementation

#### 1. Create Auth Service Structure
```bash
# Create auth service
cd services/auth
npm init -y
npm install express bcrypt jsonwebtoken speakeasy qrcode passport passport-jwt passport-local
npm install -D @types/express @types/bcrypt @types/jsonwebtoken @types/passport @types/passport-jwt @types/passport-local typescript nodemon

# Create folder structure
mkdir -p src/{controllers,services,middleware,routes,utils,validators,types}
touch src/index.ts
```

#### 2. Auth Service Configuration
```typescript
// services/auth/src/config/index.ts
import { config } from 'dotenv';
import path from 'path';

// Load environment variables
config({ path: path.join(__dirname, '../../../../.env') });

export const authConfig = {
  port: process.env.AUTH_SERVICE_PORT || 4001,
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    algorithm: 'HS256' as const,
  },
  bcrypt: {
    saltRounds: 12,
  },
  twoFA: {
    appName: process.env.TWO_FA_APP_NAME || 'NutritionPlatform',
    window: 1, // Allow 30 seconds time window
  },
  email: {
    verificationExpiry: 24 * 60 * 60 * 1000, // 24 hours
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5, // Limit each IP to 5 requests per windowMs
  },
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true,
  },
};
```

#### 3. Auth Types & Interfaces
```typescript
// services/auth/src/types/auth.types.ts
export interface JWTPayload {
  userId: string;
  email: string;
  role: UserRole;
  sessionId?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface RegisterDTO {
  email: string;
  password: string;
  phone?: string;
  firstName: string;
  lastName: string;
  acceptTerms: boolean;
}

export interface LoginDTO {
  email: string;
  password: string;
  twoFactorCode?: string;
}

export interface VerifyEmailDTO {
  token: string;
}

export interface Enable2FADTO {
  password: string;
}

export interface Verify2FADTO {
  token: string;
}

export enum UserRole {
  USER = 'USER',
  NUTRITIONIST = 'NUTRITIONIST',
  ADMIN = 'ADMIN',
}

export interface SessionData {
  userId: string;
  deviceInfo: {
    userAgent: string;
    ip: string;
    device?: string;
    browser?: string;
  };
  lastActivity: Date;
}
```

#### 4. JWT Service Implementation
```typescript
// services/auth/src/services/jwt.service.ts
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { authConfig } from '../config';
import { JWTPayload, AuthTokens } from '../types/auth.types';
import { redisClient } from '../utils/redis';
import { prisma } from '@nutrition/database';

export class JWTService {
  private static readonly ACCESS_TOKEN_PREFIX = 'access_token:';
  private static readonly REFRESH_TOKEN_PREFIX = 'refresh_token:';
  private static readonly BLACKLIST_PREFIX = 'blacklist:';

  static async generateTokens(payload: JWTPayload): Promise<AuthTokens> {
    const sessionId = uuidv4();
    const tokenPayload = { ...payload, sessionId };

    // Generate access token
    const accessToken = jwt.sign(
      tokenPayload,
      authConfig.jwt.secret,
      {
        expiresIn: authConfig.jwt.expiresIn,
        algorithm: authConfig.jwt.algorithm,
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { userId: payload.userId, sessionId },
      authConfig.jwt.refreshSecret,
      {
        expiresIn: authConfig.jwt.refreshExpiresIn,
        algorithm: authConfig.jwt.algorithm,
      }
    );

    // Store refresh token in database
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    await prisma.refreshToken.create({
      data: {
        userId: payload.userId,
        token: refreshToken,
        expiresAt,
      },
    });

    // Store session in Redis
    await redisClient.setex(
      `${this.ACCESS_TOKEN_PREFIX}${sessionId}`,
      15 * 60, // 15 minutes
      JSON.stringify(payload)
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: 15 * 60, // 15 minutes in seconds
    };
  }

  static async verifyAccessToken(token: string): Promise<JWTPayload> {
    try {
      // Check if token is blacklisted
      const isBlacklisted = await redisClient.get(`${this.BLACKLIST_PREFIX}${token}`);
      if (isBlacklisted) {
        throw new Error('Token is blacklisted');
      }

      const decoded = jwt.verify(token, authConfig.jwt.secret) as JWTPayload & { sessionId: string };
      
      // Verify session exists
      const session = await redisClient.get(`${this.ACCESS_TOKEN_PREFIX}${decoded.sessionId}`);
      if (!session) {
        throw new Error('Session not found');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  static async verifyRefreshToken(token: string): Promise<{ userId: string; sessionId: string }> {
    try {
      const decoded = jwt.verify(token, authConfig.jwt.refreshSecret) as { userId: string; sessionId: string };
      
      // Check if refresh token exists in database
      const refreshToken = await prisma.refreshToken.findUnique({
        where: { token },
      });

      if (!refreshToken || refreshToken.expiresAt < new Date()) {
        throw new Error('Invalid refresh token');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  static async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const { userId } = await this.verifyRefreshToken(refreshToken);

    // Get user details
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Delete old refresh token
    await prisma.refreshToken.delete({
      where: { token: refreshToken },
    });

    // Generate new tokens
    return this.generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role,
    });
  }

  static async revokeToken(token: string, sessionId?: string): Promise<void> {
    // Add token to blacklist
    const decoded = jwt.decode(token) as any;
    if (decoded && decoded.exp) {
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await redisClient.setex(`${this.BLACKLIST_PREFIX}${token}`, ttl, '1');
      }
    }

    // Remove session if provided
    if (sessionId) {
      await redisClient.del(`${this.ACCESS_TOKEN_PREFIX}${sessionId}`);
    }
  }

  static async revokeAllUserTokens(userId: string): Promise<void> {
    // Delete all refresh tokens
    await prisma.refreshToken.deleteMany({
      where: { userId },
    });

    // Note: Access tokens will expire naturally or need to track sessions differently
  }
}
```

#### 5. Password Service
```typescript
// services/auth/src/services/password.service.ts
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { authConfig } from '../config';
import { redisClient } from '../utils/redis';

export class PasswordService {
  private static readonly RESET_TOKEN_PREFIX = 'password_reset:';
  private static readonly RESET_TOKEN_EXPIRY = 3600; // 1 hour

  static async hash(password: string): Promise<string> {
    return bcrypt.hash(password, authConfig.bcrypt.saltRounds);
  }

  static async compare(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  static validateStrength(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async generateResetToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Store in Redis with expiry
    await redisClient.setex(
      `${this.RESET_TOKEN_PREFIX}${hashedToken}`,
      this.RESET_TOKEN_EXPIRY,
      userId
    );

    return token;
  }

  static async verifyResetToken(token: string): Promise<string | null> {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const userId = await redisClient.get(`${this.RESET_TOKEN_PREFIX}${hashedToken}`);

    if (!userId) {
      return null;
    }

    // Delete token after verification
    await redisClient.del(`${this.RESET_TOKEN_PREFIX}${hashedToken}`);
    return userId;
  }
}
```

#### 6. Two-Factor Authentication Service
```typescript
// services/auth/src/services/twoFA.service.ts
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { authConfig } from '../config';
import { prisma } from '@nutrition/database';

export class TwoFAService {
  static generateSecret(email: string): speakeasy.GeneratedSecret {
    return speakeasy.generateSecret({
      name: `${authConfig.twoFA.appName} (${email})`,
      length: 32,
    });
  }

  static async generateQRCode(secret: speakeasy.GeneratedSecret): Promise<string> {
    return QRCode.toDataURL(secret.otpauth_url!);
  }

  static verifyToken(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: authConfig.twoFA.window,
    });
  }

  static async enableTwoFA(userId: string, secret: string): Promise<string[]> {
    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      Math.random().toString(36).substring(2, 10).toUpperCase()
    );

    // Hash backup codes
    const hashedCodes = await Promise.all(
      backupCodes.map(code => bcrypt.hash(code, 10))
    );

    // Update user
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFASecret: secret,
        twoFAEnabled: true,
        twoFABackupCodes: hashedCodes,
      },
    });

    return backupCodes;
  }

  static async disableTwoFA(userId: string): Promise<void> {
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFASecret: null,
        twoFAEnabled: false,
        twoFABackupCodes: [],
      },
    });
  }

  static async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { twoFABackupCodes: true },
    });

    if (!user || !user.twoFABackupCodes) {
      return false;
    }

    // Check each backup code
    for (let i = 0; i < user.twoFABackupCodes.length; i++) {
      const isValid = await bcrypt.compare(code, user.twoFABackupCodes[i]);
      if (isValid) {
        // Remove used backup code
        const newCodes = [...user.twoFABackupCodes];
        newCodes.splice(i, 1);

        await prisma.user.update({
          where: { id: userId },
          data: { twoFABackupCodes: newCodes },
        });

        return true;
      }
    }

    return false;
  }
}
```

### Day 3-4: Auth Controllers & Middleware

#### 1. Auth Controller Implementation
```typescript
// services/auth/src/controllers/auth.controller.ts
import { Request, Response, NextFunction } from 'express';
import { prisma } from '@nutrition/database';
import { JWTService } from '../services/jwt.service';
import { PasswordService } from '../services/password.service';
import { TwoFAService } from '../services/twoFA.service';
import { EmailService } from '../services/email.service';
import { RegisterDTO, LoginDTO } from '../types/auth.types';
import { validateRegister, validateLogin } from '../validators/auth.validator';
import { AppError } from '../utils/errors';
import { auditLog } from '../utils/audit';

export class AuthController {
  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const body: RegisterDTO = req.body;

      // Validate input
      const validation = validateRegister(body);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      // Check if user exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { email: body.email },
            { phone: body.phone || undefined },
          ],
        },
      });

      if (existingUser) {
        throw new AppError('User already exists', 409);
      }

      // Validate password strength
      const passwordValidation = PasswordService.validateStrength(body.password);
      if (!passwordValidation.valid) {
        throw new AppError('Weak password', 400, passwordValidation.errors);
      }

      // Hash password
      const passwordHash = await PasswordService.hash(body.password);

      // Create user in transaction
      const user = await prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: {
            email: body.email,
            phone: body.phone,
            passwordHash,
            profile: {
              create: {
                firstName: body.firstName,
                lastName: body.lastName,
              },
            },
          },
          include: {
            profile: true,
          },
        });

        // Create audit log
        await auditLog({
          userId: newUser.id,
          action: 'REGISTER',
          entity: 'user',
          entityId: newUser.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        });

        return newUser;
      });

      // Send verification email
      const verificationToken = await EmailService.sendVerificationEmail(
        user.email,
        user.profile!.firstName
      );

      // Generate tokens
      const tokens = await JWTService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful. Please verify your email.',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.profile!.firstName,
            lastName: user.profile!.lastName,
            emailVerified: user.emailVerified,
          },
          tokens,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const body: LoginDTO = req.body;

      // Validate input
      const validation = validateLogin(body);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      // Find user
      const user = await prisma.user.findUnique({
        where: { email: body.email },
        include: {
          profile: true,
        },
      });

      if (!user) {
        throw new AppError('Invalid credentials', 401);
      }

      // Verify password
      const isValidPassword = await PasswordService.compare(
        body.password,
        user.passwordHash
      );

      if (!isValidPassword) {
        // Log failed attempt
        await auditLog({
          userId: user.id,
          action: 'LOGIN_FAILED',
          entity: 'user',
          entityId: user.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        });

        throw new AppError('Invalid credentials', 401);
      }

      // Check if 2FA is enabled
      if (user.twoFAEnabled) {
        if (!body.twoFactorCode) {
          return res.status(200).json({
            success: true,
            message: 'Two-factor authentication required',
            data: {
              requiresTwoFactor: true,
              userId: user.id,
            },
          });
        }

        // Verify 2FA code
        const isValid2FA = TwoFAService.verifyToken(
          user.twoFASecret!,
          body.twoFactorCode
        );

        if (!isValid2FA) {
          // Check backup code
          const isValidBackup = await TwoFAService.verifyBackupCode(
            user.id,
            body.twoFactorCode
          );

          if (!isValidBackup) {
            throw new AppError('Invalid two-factor code', 401);
          }
        }
      }

      // Update last login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });

      // Generate tokens
      const tokens = await JWTService.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      // Log successful login
      await auditLog({
        userId: user.id,
        action: 'LOGIN',
        entity: 'user',
        entityId: user.id,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.profile!.firstName,
            lastName: user.profile!.lastName,
            emailVerified: user.emailVerified,
            twoFAEnabled: user.twoFAEnabled,
          },
          tokens,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async logout(req: Request, res: Response, next: NextFunction) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      const { userId, sessionId } = req.user!;

      if (token) {
        await JWTService.revokeToken(token, sessionId);
      }

      // Log logout
      await auditLog({
        userId,
        action: 'LOGOUT',
        entity: 'user',
        entityId: userId,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      res.json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      next(error);
    }
  }

  static async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw new AppError('Refresh token required', 400);
      }

      const tokens = await JWTService.refreshTokens(refreshToken);

      res.json({
        success: true,
        data: { tokens },
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.body;

      const userId = await EmailService.verifyEmailToken(token);
      if (!userId) {
        throw new AppError('Invalid or expired token', 400);
      }

      await prisma.user.update({
        where: { id: userId },
        data: { emailVerified: true },
      });

      res.json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async enable2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password } = req.body;

      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const isValidPassword = await PasswordService.compare(
        password,
        user.passwordHash
      );

      if (!isValidPassword) {
        throw new AppError('Invalid password', 401);
      }

      // Generate secret
      const secret = TwoFAService.generateSecret(user.email);
      const qrCode = await TwoFAService.generateQRCode(secret);

      // Store secret temporarily
      await redisClient.setex(
        `2fa_setup:${userId}`,
        600, // 10 minutes
        secret.base32
      );

      res.json({
        success: true,
        data: {
          secret: secret.base32,
          qrCode,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async confirm2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { token } = req.body;

      // Get temporary secret
      const secret = await redisClient.get(`2fa_setup:${userId}`);
      if (!secret) {
        throw new AppError('2FA setup expired', 400);
      }

      // Verify token
      const isValid = TwoFAService.verifyToken(secret, token);
      if (!isValid) {
        throw new AppError('Invalid token', 400);
      }

      // Enable 2FA and get backup codes
      const backupCodes = await TwoFAService.enableTwoFA(userId, secret);

      // Clean up temporary secret
      await redisClient.del(`2fa_setup:${userId}`);

      res.json({
        success: true,
        message: '2FA enabled successfully',
        data: {
          backupCodes,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async disable2FA(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password, token } = req.body;

      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const isValidPassword = await PasswordService.compare(
        password,
        user.passwordHash
      );

      if (!isValidPassword) {
        throw new AppError('Invalid password', 401);
      }

      // Verify 2FA token
      if (user.twoFAEnabled && user.twoFASecret) {
        const isValid = TwoFAService.verifyToken(user.twoFASecret, token);
        if (!isValid) {
          throw new AppError('Invalid 2FA token', 401);
        }
      }

      // Disable 2FA
      await TwoFAService.disableTwoFA(userId);

      res.json({
        success: true,
        message: '2FA disabled successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body;

      const user = await prisma.user.findUnique({
        where: { email },
        include: { profile: true },
      });

      if (!user) {
        // Don't reveal if user exists
        return res.json({
          success: true,
          message: 'If the email exists, a reset link has been sent',
        });
      }

      // Generate reset token
      const resetToken = await PasswordService.generateResetToken(user.id);

      // Send reset email
      await EmailService.sendPasswordResetEmail(
        user.email,
        user.profile!.firstName,
        resetToken
      );

      res.json({
        success: true,
        message: 'If the email exists, a reset link has been sent',
      });
    } catch (error) {
      next(error);
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { token, password } = req.body;

      // Verify token
      const userId = await PasswordService.verifyResetToken(token);
      if (!userId) {
        throw new AppError('Invalid or expired token', 400);
      }

      // Validate password
      const passwordValidation = PasswordService.validateStrength(password);
      if (!passwordValidation.valid) {
        throw new AppError('Weak password', 400, passwordValidation.errors);
      }

      // Hash and update password
      const passwordHash = await PasswordService.hash(password);
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash },
      });

      // Revoke all tokens
      await JWTService.revokeAllUserTokens(userId);

      res.json({
        success: true,
        message: 'Password reset successful',
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Auth Middleware
```typescript
// services/auth/src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { JWTService } from '../services/jwt.service';
import { AppError } from '../utils/errors';
import { UserRole } from '../types/auth.types';

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        role: UserRole;
        sessionId?: string;
      };
    }
  }
}

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError('No token provided', 401);
    }

    const token = authHeader.split(' ')[1];
    const payload = await JWTService.verifyAccessToken(token);

    req.user = payload;
    next();
  } catch (error) {
    next(new AppError('Invalid token', 401));
  }
};

export const authorize = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Unauthorized', 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(new AppError('Forbidden', 403));
    }

    next();
  };
};

export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    const token = authHeader.split(' ')[1];
    const payload = await JWTService.verifyAccessToken(token);

    req.user = payload;
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};
```

### Day 5-7: Email Service & Templates

#### 1. Email Service Implementation
```typescript
// services/auth/src/services/email.service.ts
import nodemailer from 'nodemailer';
import mjml2html from 'mjml';
import { redisClient } from '../utils/redis';
import { authConfig } from '../config';
import crypto from 'crypto';

export class EmailService {
  private static transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  private static readonly VERIFICATION_PREFIX = 'email_verify:';
  private static readonly VERIFICATION_EXPIRY = 24 * 60 * 60; // 24 hours

  static async sendVerificationEmail(
    email: string,
    firstName: string
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Store token with user email
    await redisClient.setex(
      `${this.VERIFICATION_PREFIX}${hashedToken}`,
      this.VERIFICATION_EXPIRY,
      email
    );

    const verificationUrl = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Verify Your Email</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
          <mj-attributes>
            <mj-all font-family="Inter, Arial, sans-serif" />
            <mj-text font-size="16px" color="#333333" line-height="24px" />
            <mj-section background-color="#f4f4f4" />
          </mj-attributes>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="28px" font-weight="700" color="#1a1a1a" align="center">
                Welcome to Nutrition Platform!
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Hi ${firstName},
              </mj-text>
              <mj-text>
                Thank you for signing up! Please verify your email address to get started on your wellness journey.
              </mj-text>
              <mj-spacer height="30px" />
              <mj-button 
                background-color="#10b981" 
                color="#ffffff" 
                font-size="16px" 
                font-weight="600"
                padding="15px 30px"
                border-radius="6px"
                href="${verificationUrl}"
              >
                Verify Email Address
              </mj-button>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                Or copy and paste this link into your browser:
              </mj-text>
              <mj-text font-size="14px" color="#10b981">
                ${verificationUrl}
              </mj-text>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                This link will expire in 24 hours. If you didn't create an account, you can safely ignore this email.
              </mj-text>
            </mj-column>
          </mj-section>
          <mj-section padding="20px">
            <mj-column>
              <mj-text align="center" font-size="14px" color="#666666">
                © 2024 Nutrition Platform. All rights reserved.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Verify Your Email - Nutrition Platform',
      html,
    });

    return token;
  }

  static async verifyEmailToken(token: string): Promise<string | null> {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const email = await redisClient.get(`${this.VERIFICATION_PREFIX}${hashedToken}`);

    if (!email) {
      return null;
    }

    // Delete token after verification
    await redisClient.del(`${this.VERIFICATION_PREFIX}${hashedToken}`);
    return email;
  }

  static async sendPasswordResetEmail(
    email: string,
    firstName: string,
    resetToken: string
  ): Promise<void> {
    const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}`;

    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Reset Your Password</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
          <mj-attributes>
            <mj-all font-family="Inter, Arial, sans-serif" />
            <mj-text font-size="16px" color="#333333" line-height="24px" />
            <mj-section background-color="#f4f4f4" />
          </mj-attributes>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="28px" font-weight="700" color="#1a1a1a" align="center">
                Reset Your Password
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>
                Hi ${firstName},
              </mj-text>
              <mj-text>
                We received a request to reset your password. Click the button below to create a new password.
              </mj-text>
              <mj-spacer height="30px" />
              <mj-button 
                background-color="#10b981" 
                color="#ffffff" 
                font-size="16px" 
                font-weight="600"
                padding="15px 30px"
                border-radius="6px"
                href="${resetUrl}"
              >
                Reset Password
              </mj-button>
              <mj-spacer height="30px" />
              <mj-text font-size="14px" color="#666666">
                This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text font-size="14px" color="#dc2626" font-weight="600">
                Security Tip: Never share your password with anyone, including our support team.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Reset Your Password - Nutrition Platform',
      html,
    });
  }

  static async sendWelcomeEmail(
    email: string,
    firstName: string
  ): Promise<void> {
    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Welcome to Your Wellness Journey</mj-title>
          <mj-font name="Inter" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" />
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="32px" font-weight="700" color="#1a1a1a" align="center">
                Welcome, ${firstName}! 🌱
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text font-size="18px" align="center" color="#666666">
                Your journey to better health starts now
              </mj-text>
              <mj-spacer height="40px" />
              <mj-text>
                We're thrilled to have you join our community! Here's what you can do next:
              </mj-text>
              <mj-spacer height="20px" />
              
              <!-- Getting Started Steps -->
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    🎯 1. Take the Health Assessment Quiz
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    Get personalized recommendations based on your health goals
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/quiz/health-assessment"
                  >
                    Start Quiz
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="15px" />
              
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    📅 2. Book Your Free Discovery Call
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    20-minute consultation to discuss your wellness goals
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/book-consultation"
                  >
                    Book Now
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="15px" />
              
              <mj-wrapper padding="20px" background-color="#f8fafc" border-radius="6px">
                <mj-column>
                  <mj-text font-weight="600" font-size="18px">
                    📚 3. Explore Our Resources
                  </mj-text>
                  <mj-text font-size="14px" color="#666666">
                    Free guides, meal plans, and health tips
                  </mj-text>
                  <mj-button 
                    background-color="#10b981" 
                    color="#ffffff" 
                    font-size="14px"
                    padding="10px 20px"
                    border-radius="4px"
                    href="${process.env.CLIENT_URL}/resources"
                  >
                    Browse Resources
                  </mj-button>
                </mj-column>
              </mj-wrapper>
              
              <mj-spacer height="40px" />
              
              <mj-text align="center" font-size="14px" color="#666666">
                Questions? Reply to this email or reach out to us at support@nutritionplatform.com
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: 'Welcome to Your Wellness Journey! 🌱',
      html,
    });
  }

  static async send2FAEmail(
    email: string,
    firstName: string,
    code: string
  ): Promise<void> {
    const mjml = `
      <mjml>
        <mj-head>
          <mj-title>Your Login Code</mj-title>
        </mj-head>
        <mj-body background-color="#f4f4f4">
          <mj-section background-color="#ffffff" padding="40px 20px" border-radius="8px">
            <mj-column>
              <mj-text font-size="24px" font-weight="700" align="center">
                Your Login Code
              </mj-text>
              <mj-spacer height="20px" />
              <mj-text>Hi ${firstName},</mj-text>
              <mj-text>
                Here's your temporary login code:
              </mj-text>
              <mj-spacer height="20px" />
              <mj-wrapper background-color="#f8fafc" padding="20px" border-radius="6px">
                <mj-column>
                  <mj-text font-size="32px" font-weight="700" align="center" letter-spacing="8px">
                    ${code}
                  </mj-text>
                </mj-column>
              </mj-wrapper>
              <mj-spacer height="20px" />
              <mj-text font-size="14px" color="#666666">
                This code will expire in 5 minutes. If you didn't request this, please ignore this email.
              </mj-text>
            </mj-column>
          </mj-section>
        </mj-body>
      </mjml>
    `;

    const { html } = mjml2html(mjml);

    await this.transporter.sendMail({
      from: `Nutrition Platform <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: `Your Login Code: ${code}`,
      html,
    });
  }
}
```

## Week 3: User Service & Profile Management

### Day 1-2: User Service Setup

#### 1. User Service Structure
```typescript
// services/user/src/index.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { errorHandler } from './middleware/error.middleware';
import { requestLogger } from './middleware/logger.middleware';
import { rateLimiter } from './middleware/rateLimit.middleware';
import userRoutes from './routes/user.routes';
import profileRoutes from './routes/profile.routes';
import documentRoutes from './routes/document.routes';

const app = express();
const PORT = process.env.USER_SERVICE_PORT || 4002;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);
app.use(rateLimiter);

// Routes
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/profiles', profileRoutes);
app.use('/api/v1/documents', documentRoutes);

// Error handling
app.use(errorHandler);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'user-service' });
});

app.listen(PORT, () => {
  console.log(`User Service running on port ${PORT}`);
});
```

#### 2. User Controller
```typescript
// services/user/src/controllers/user.controller.ts
import { Request, Response, NextFunction } from 'express';
import { prisma } from '@nutrition/database';
import { UserService } from '../services/user.service';
import { ProfileService } from '../services/profile.service';
import { AppError } from '../utils/errors';
import { uploadToStorage } from '../utils/storage';

export class UserController {
  static async getProfile(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const profile = await ProfileService.getFullProfile(userId);

      if (!profile) {
        throw new AppError('Profile not found', 404);
      }

      res.json({
        success: true,
        data: profile,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateProfile(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const updates = req.body;

      // Validate updates
      const validation = ProfileService.validateProfileUpdate(updates);
      if (!validation.valid) {
        throw new AppError('Validation failed', 400, validation.errors);
      }

      const updatedProfile = await ProfileService.updateProfile(userId, updates);

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: updatedProfile,
      });
    } catch (error) {
      next(error);
    }
  }

  static async uploadAvatar(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const file = req.file;

      if (!file) {
        throw new AppError('No file uploaded', 400);
      }

      // Validate file
      const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid file type', 400);
      }

      if (file.size > 5 * 1024 * 1024) { // 5MB
        throw new AppError('File too large', 400);
      }

      // Process and upload image
      const avatarUrl = await ProfileService.updateAvatar(userId, file);

      res.json({
        success: true,
        message: 'Avatar updated successfully',
        data: { avatarUrl },
      });
    } catch (error) {
      next(error);
    }
  }

  static async getMedicalHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const history = await UserService.getMedicalHistory(userId);

      res.json({
        success: true,
        data: history,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateMedicalHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const medicalData = req.body;

      const updated = await UserService.updateMedicalHistory(userId, medicalData);

      res.json({
        success: true,
        message: 'Medical history updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getHealthMetrics(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { startDate, endDate } = req.query;

      const metrics = await UserService.getHealthMetrics(
        userId,
        startDate as string,
        endDate as string
      );

      res.json({
        success: true,
        data: metrics,
      });
    } catch (error) {
      next(error);
    }
  }

  static async addHealthMetric(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const metricData = req.body;

      const metric = await UserService.addHealthMetric(userId, metricData);

      res.json({
        success: true,
        message: 'Health metric added successfully',
        data: metric,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const preferences = await UserService.getPreferences(userId);

      res.json({
        success: true,
        data: preferences,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updatePreferences(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const preferences = req.body;

      const updated = await UserService.updatePreferences(userId, preferences);

      res.json({
        success: true,
        message: 'Preferences updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteAccount(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { password, reason } = req.body;

      // Verify password
      const isValid = await UserService.verifyPassword(userId, password);
      if (!isValid) {
        throw new AppError('Invalid password', 401);
      }

      // Schedule account deletion
      await UserService.scheduleAccountDeletion(userId, reason);

      res.json({
        success: true,
        message: 'Account deletion scheduled. You have 30 days to cancel this request.',
      });
    } catch (error) {
      next(error);
    }
  }

  static async exportUserData(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      // Generate export
      const exportUrl = await UserService.exportUserData(userId);

      res.json({
        success: true,
        message: 'Your data export is ready',
        data: { downloadUrl: exportUrl },
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 3. Profile Service
```typescript
// services/user/src/services/profile.service.ts
import { prisma } from '@nutrition/database';
import sharp from 'sharp';
import { uploadToStorage, deleteFromStorage } from '../utils/storage';
import { calculateBMI, calculateBMR } from '../utils/health.calculations';

export class ProfileService {
  static async getFullProfile(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        profile: true,
        journeys: {
          include: {
            program: true,
          },
          orderBy: {
            startDate: 'desc',
          },
          take: 1,
        },
        consultations: {
          where: {
            status: 'COMPLETED',
          },
          orderBy: {
            completedAt: 'desc',
          },
          take: 5,
        },
      },
    });

    if (!user) {
      return null;
    }

    // Calculate additional metrics
    const metrics = user.profile
      ? {
          bmi: calculateBMI(user.profile.weight, user.profile.height),
          bmr: calculateBMR(
            user.profile.weight,
            user.profile.height,
            user.profile.dateOfBirth,
            user.profile.gender
          ),
        }
      : null;

    return {
      ...user,
      metrics,
    };
  }

  static validateProfileUpdate(data: any) {
    const errors: string[] = [];

    if (data.height && (data.height < 50 || data.height > 300)) {
      errors.push('Height must be between 50 and 300 cm');
    }

    if (data.weight && (data.weight < 20 || data.weight > 500)) {
      errors.push('Weight must be between 20 and 500 kg');
    }

    if (data.dateOfBirth) {
      const age = new Date().getFullYear() - new Date(data.dateOfBirth).getFullYear();
      if (age < 13 || age > 120) {
        errors.push('Age must be between 13 and 120 years');
      }
    }

    if (data.phone && !/^[+]?[0-9]{10,15}$/.test(data.phone)) {
      errors.push('Invalid phone number format');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async updateProfile(userId: string, updates: any) {
    const { allergies, medications, ...profileData } = updates;

    const updatedProfile = await prisma.userProfile.update({
      where: { userId },
      data: {
        ...profileData,
        allergies: allergies ? { set: allergies } : undefined,
        medications: medications ? { set: medications } : undefined,
      },
    });

    // Update phone in user table if provided
    if (updates.phone) {
      await prisma.user.update({
        where: { id: userId },
        data: { phone: updates.phone },
      });
    }

    return updatedProfile;
  }

  static async updateAvatar(userId: string, file: Express.Multer.File) {
    // Get current avatar to delete later
    const profile = await prisma.userProfile.findUnique({
      where: { userId },
      select: { avatar: true },
    });

    // Process image
    const processedImage = await sharp(file.buffer)
      .resize(400, 400, {
        fit: 'cover',
        position: 'center',
      })
      .jpeg({ quality: 90 })
      .toBuffer();

    // Upload to storage
    const filename = `avatars/${userId}-${Date.now()}.jpg`;
    const avatarUrl = await uploadToStorage(processedImage, filename, 'image/jpeg');

    // Update profile
    await prisma.userProfile.update({
      where: { userId },
      data: { avatar: avatarUrl },
    });

    // Delete old avatar if exists
    if (profile?.avatar) {
      await deleteFromStorage(profile.avatar).catch(console.error);
    }

    return avatarUrl;
  }

  static async createInitialProfile(userId: string, data: any) {
    return prisma.userProfile.create({
      data: {
        userId,
        firstName: data.firstName,
        lastName: data.lastName,
        ...data,
      },
    });
  }
}
```

### Day 3-4: Document Management

#### 1. Document Controller
```typescript
// services/user/src/controllers/document.controller.ts
import { Request, Response, NextFunction } from 'express';
import { DocumentService } from '../services/document.service';
import { AppError } from '../utils/errors';

export class DocumentController {
  static async uploadDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { type, title, description } = req.body;
      const file = req.file;

      if (!file) {
        throw new AppError('No file uploaded', 400);
      }

      // Validate file type
      const allowedTypes = [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      ];

      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid file type', 400);
      }

      // File size limit: 10MB
      if (file.size > 10 * 1024 * 1024) {
        throw new AppError('File too large (max 10MB)', 400);
      }

      const document = await DocumentService.uploadDocument(userId, {
        type,
        title,
        description,
        file,
      });

      res.status(201).json({
        success: true,
        message: 'Document uploaded successfully',
        data: document,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocuments(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { type, page = 1, limit = 20 } = req.query;

      const documents = await DocumentService.getUserDocuments(userId, {
        type: type as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: documents,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const document = await DocumentService.getDocument(id, userId);

      if (!document) {
        throw new AppError('Document not found', 404);
      }

      res.json({
        success: true,
        data: document,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getDocumentUrl(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const url = await DocumentService.getSignedUrl(id, userId);

      res.json({
        success: true,
        data: { url },
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      await DocumentService.deleteDocument(id, userId);

      res.json({
        success: true,
        message: 'Document deleted successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async archiveDocument(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      await DocumentService.archiveDocument(id, userId);

      res.json({
        success: true,
        message: 'Document archived successfully',
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Document Service
```typescript
// services/user/src/services/document.service.ts
import { prisma } from '@nutrition/database';
import { uploadToStorage, deleteFromStorage, getSignedUrl } from '../utils/storage';
import crypto from 'crypto';
import { scanFile } from '../utils/antivirus';

interface UploadDocumentDto {
  type: string;
  title: string;
  description?: string;
  file: Express.Multer.File;
}

export class DocumentService {
  static async uploadDocument(userId: string, data: UploadDocumentDto) {
    // Scan file for viruses
    const isSafe = await scanFile(data.file.buffer);
    if (!isSafe) {
      throw new Error('File failed security scan');
    }

    // Generate unique filename
    const fileExt = data.file.originalname.split('.').pop();
    const filename = `documents/${userId}/${crypto.randomBytes(16).toString('hex')}.${fileExt}`;

    // Upload to storage
    const fileUrl = await uploadToStorage(
      data.file.buffer,
      filename,
      data.file.mimetype
    );

    // Create document record
    const document = await prisma.document.create({
      data: {
        userId,
        type: data.type,
        title: data.title,
        description: data.description,
        fileUrl,
        fileSize: data.file.size,
        mimeType: data.file.mimetype,
      },
    });

    return document;
  }

  static async getUserDocuments(
    userId: string,
    options: { type?: string; page: number; limit: number }
  ) {
    const where = {
      userId,
      isArchived: false,
      ...(options.type && { type: options.type }),
    };

    const [documents, total] = await Promise.all([
      prisma.document.findMany({
        where,
        orderBy: { uploadedAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
      }),
      prisma.document.count({ where }),
    ]);

    return {
      documents,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getDocument(documentId: string, userId: string) {
    return prisma.document.findFirst({
      where: {
        id: documentId,
        userId,
      },
    });
  }

  static async getSignedUrl(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    return getSignedUrl(document.fileUrl, 3600); // 1 hour expiry
  }

  static async deleteDocument(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    // Delete from storage
    await deleteFromStorage(document.fileUrl);

    // Delete from database
    await prisma.document.delete({
      where: { id: documentId },
    });
  }

  static async archiveDocument(documentId: string, userId: string) {
    const document = await this.getDocument(documentId, userId);
    
    if (!document) {
      throw new Error('Document not found');
    }

    await prisma.document.update({
      where: { id: documentId },
      data: { isArchived: true },
    });
  }

  static async getDocumentsByType(userId: string, type: string) {
    return prisma.document.findMany({
      where: {
        userId,
        type,
        isArchived: false,
      },
      orderBy: { uploadedAt: 'desc' },
    });
  }
}
```

### Day 3-4: Consultation Booking Service

#### 1. Consultation Controller
```typescript
// services/consultation/src/controllers/consultation.controller.ts
import { Request, Response, NextFunction } from 'express';
import { ConsultationService } from '../services/consultation.service';
import { CalendarService } from '../services/calendar.service';
import { AppError } from '../utils/errors';

export class ConsultationController {
  static async getAvailableSlots(req: Request, res: Response, next: NextFunction) {
    try {
      const { nutritionistId, date, timezone = 'Asia/Kolkata' } = req.query;

      if (!nutritionistId || !date) {
        throw new AppError('Nutritionist ID and date are required', 400);
      }

      const slots = await CalendarService.getAvailableSlots(
        nutritionistId as string,
        new Date(date as string),
        timezone as string
      );

      res.json({
        success: true,
        data: slots,
      });
    } catch (error) {
      next(error);
    }
  }

  static async bookConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const {
        nutritionistId,
        programId,
        scheduledAt,
        duration = 60,
        notes,
        timezone = 'Asia/Kolkata',
      } = req.body;

      // Validate slot availability
      const isAvailable = await CalendarService.checkSlotAvailability(
        nutritionistId,
        new Date(scheduledAt),
        duration
      );

      if (!isAvailable) {
        throw new AppError('Selected time slot is not available', 400);
      }

      const consultation = await ConsultationService.bookConsultation({
        userId,
        nutritionistId,
        programId,
        scheduledAt: new Date(scheduledAt),
        duration,
        notes,
        timezone,
      });

      res.status(201).json({
        success: true,
        message: 'Consultation booked successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUserConsultations(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { status, page = 1, limit = 10 } = req.query;

      const consultations = await ConsultationService.getUserConsultations(userId, {
        status: status as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: consultations,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const consultation = await ConsultationService.getConsultation(id, userId);

      if (!consultation) {
        throw new AppError('Consultation not found', 404);
      }

      res.json({
        success: true,
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async rescheduleConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { scheduledAt, reason } = req.body;

      const consultation = await ConsultationService.rescheduleConsultation(
        id,
        userId,
        new Date(scheduledAt),
        reason
      );

      res.json({
        success: true,
        message: 'Consultation rescheduled successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async cancelConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { reason } = req.body;

      await ConsultationService.cancelConsultation(id, userId, reason);

      res.json({
        success: true,
        message: 'Consultation cancelled successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async joinConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;

      const meetingInfo = await ConsultationService.getMeetingInfo(id, userId);

      res.json({
        success: true,
        data: meetingInfo,
      });
    } catch (error) {
      next(error);
    }
  }

  static async completeConsultation(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { notes, prescription, followUpDate } = req.body;

      // Only nutritionist can complete consultation
      const consultation = await ConsultationService.completeConsultation(id, {
        nutritionistId: userId,
        notes,
        prescription,
        followUpDate,
      });

      res.json({
        success: true,
        message: 'Consultation completed successfully',
        data: consultation,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUpcomingReminders(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const reminders = await ConsultationService.getUpcomingReminders(userId);

      res.json({
        success: true,
        data: reminders,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Consultation Service
```typescript
// services/consultation/src/services/consultation.service.ts
import { prisma } from '@nutrition/database';
import { VideoService } from './video.service';
import { NotificationService } from './notification.service';
import { CalendarService } from './calendar.service';
import { PaymentService } from './payment.service';
import { addMinutes, subHours, isAfter, isBefore } from 'date-fns';

interface BookConsultationDto {
  userId: string;
  nutritionistId: string;
  programId?: string;
  scheduledAt: Date;
  duration: number;
  notes?: string;
  timezone: string;
}

export class ConsultationService {
  static async bookConsultation(data: BookConsultationDto) {
    // Start transaction
    return prisma.$transaction(async (tx) => {
      // Check for conflicts
      const conflicts = await tx.consultation.findMany({
        where: {
          OR: [
            { userId: data.userId },
            { nutritionistId: data.nutritionistId },
          ],
          scheduledAt: {
            gte: data.scheduledAt,
            lt: addMinutes(data.scheduledAt, data.duration),
          },
          status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
        },
      });

      if (conflicts.length > 0) {
        throw new Error('Time slot conflict detected');
      }

      // Get nutritionist details for pricing
      const nutritionist = await tx.nutritionistProfile.findUnique({
        where: { userId: data.nutritionistId },
      });

      if (!nutritionist) {
        throw new Error('Nutritionist not found');
      }

      // Create consultation
      const consultation = await tx.consultation.create({
        data: {
          userId: data.userId,
          nutritionistId: data.nutritionistId,
          programId: data.programId,
          scheduledAt: data.scheduledAt,
          duration: data.duration,
          status: 'SCHEDULED',
          notes: data.notes,
        },
        include: {
          user: {
            include: { profile: true },
          },
          nutritionist: {
            include: { profile: true },
          },
        },
      });

      // Create video meeting
      const meeting = await VideoService.createMeeting({
        consultationId: consultation.id,
        topic: `Consultation with ${consultation.nutritionist.profile?.firstName}`,
        startTime: data.scheduledAt,
        duration: data.duration,
        timezone: data.timezone,
      });

      // Update consultation with meeting details
      await tx.consultation.update({
        where: { id: consultation.id },
        data: {
          meetingLink: meeting.joinUrl,
          meetingId: meeting.id,
        },
      });

      // Create calendar events
      await CalendarService.createEvents({
        consultation,
        userTimezone: data.timezone,
      });

      // Schedule reminders
      await this.scheduleReminders(consultation.id, data.scheduledAt);

      // Send confirmation emails
      await NotificationService.sendConsultationBooked(consultation);

      return consultation;
    });
  }

  static async getUserConsultations(userId: string, options: {
    status?: string;
    page: number;
    limit: number;
  }) {
    const where: any = { userId };

    if (options.status) {
      where.status = options.status;
    }

    const [consultations, total] = await Promise.all([
      prisma.consultation.findMany({
        where,
        orderBy: { scheduledAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          nutritionist: {
            include: {
              user: true,
              profile: true,
            },
          },
          program: true,
          payment: true,
        },
      }),
      prisma.consultation.count({ where }),
    ]);

    return {
      consultations,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getConsultation(consultationId: string, userId: string) {
    return prisma.consultation.findFirst({
      where: {
        id: consultationId,
        OR: [
          { userId },
          { nutritionistId: userId },
        ],
      },
      include: {
        user: {
          include: { profile: true },
        },
        nutritionist: {
          include: {
            user: true,
            profile: true,
          },
        },
        program: true,
        payment: true,
        reminders: true,
      },
    });
  }

  static async rescheduleConsultation(
    consultationId: string,
    userId: string,
    newScheduledAt: Date,
    reason: string
  ) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (consultation.status !== 'SCHEDULED') {
      throw new Error('Only scheduled consultations can be rescheduled');
    }

    // Check if within reschedule window (24 hours before)
    const rescheduleDeadline = subHours(consultation.scheduledAt, 24);
    if (isAfter(new Date(), rescheduleDeadline)) {
      throw new Error('Cannot reschedule within 24 hours of appointment');
    }

    // Check new slot availability
    const isAvailable = await CalendarService.checkSlotAvailability(
      consultation.nutritionistId,
      newScheduledAt,
      consultation.duration
    );

    if (!isAvailable) {
      throw new Error('New time slot is not available');
    }

    // Update consultation
    const updated = await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        scheduledAt: newScheduledAt,
        updatedAt: new Date(),
      },
    });

    // Update video meeting
    if (consultation.meetingId) {
      await VideoService.updateMeeting(consultation.meetingId, {
        startTime: newScheduledAt,
      });
    }

    // Cancel old reminders and schedule new ones
    await this.cancelReminders(consultationId);
    await this.scheduleReminders(consultationId, newScheduledAt);

    // Update calendar events
    await CalendarService.updateEvents({
      consultation: updated,
      oldScheduledAt: consultation.scheduledAt,
    });

    // Send notifications
    await NotificationService.sendConsultationRescheduled(updated, reason);

    return updated;
  }

  static async cancelConsultation(
    consultationId: string,
    userId: string,
    reason: string
  ) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (!['SCHEDULED', 'IN_PROGRESS'].includes(consultation.status)) {
      throw new Error('Cannot cancel this consultation');
    }

    // Check cancellation policy
    const cancellationDeadline = subHours(consultation.scheduledAt, 4);
    const isLateCancellation = isAfter(new Date(), cancellationDeadline);

    // Update consultation
    await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        status: 'CANCELLED',
        cancelledAt: new Date(),
        cancellationReason: reason,
      },
    });

    // Cancel video meeting
    if (consultation.meetingId) {
      await VideoService.cancelMeeting(consultation.meetingId);
    }

    // Cancel reminders
    await this.cancelReminders(consultationId);

    // Process refund if applicable
    if (consultation.payment && !isLateCancellation) {
      await PaymentService.processRefund(consultation.payment.id, 'full');
    }

    // Send notifications
    await NotificationService.sendConsultationCancelled(consultation, reason);
  }

  static async getMeetingInfo(consultationId: string, userId: string) {
    const consultation = await this.getConsultation(consultationId, userId);

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    // Check if it's time to join (15 minutes before to 30 minutes after)
    const now = new Date();
    const joinWindowStart = subHours(consultation.scheduledAt, 0.25); // 15 minutes before
    const joinWindowEnd = addMinutes(consultation.scheduledAt, 30);

    if (isBefore(now, joinWindowStart) || isAfter(now, joinWindowEnd)) {
      throw new Error('Meeting room is not available at this time');
    }

    // Update status if needed
    if (consultation.status === 'SCHEDULED' && isAfter(now, consultation.scheduledAt)) {
      await prisma.consultation.update({
        where: { id: consultationId },
        data: { status: 'IN_PROGRESS' },
      });
    }

    return {
      meetingLink: consultation.meetingLink,
      meetingId: consultation.meetingId,
      hostLink: userId === consultation.nutritionistId 
        ? await VideoService.getHostLink(consultation.meetingId!) 
        : null,
    };
  }

  static async completeConsultation(consultationId: string, data: {
    nutritionistId: string;
    notes?: string;
    prescription?: any;
    followUpDate?: Date;
  }) {
    const consultation = await prisma.consultation.findFirst({
      where: {
        id: consultationId,
        nutritionistId: data.nutritionistId,
      },
    });

    if (!consultation) {
      throw new Error('Consultation not found');
    }

    if (consultation.status !== 'IN_PROGRESS') {
      throw new Error('Consultation must be in progress to complete');
    }

    // Update consultation
    const updated = await prisma.consultation.update({
      where: { id: consultationId },
      data: {
        status: 'COMPLETED',
        completedAt: new Date(),
        internalNotes: data.notes,
        prescription: data.prescription,
        followUpDate: data.followUpDate,
      },
      include: {
        user: {
          include: { profile: true },
        },
      },
    });

    // Generate prescription PDF if provided
    if (data.prescription) {
      const prescriptionUrl = await this.generatePrescriptionPDF(
        updated,
        data.prescription
      );

      await prisma.consultation.update({
        where: { id: consultationId },
        data: { prescriptionUrl },
      });
    }

    // Send follow-up email with notes
    await NotificationService.sendConsultationCompleted(updated);

    // Schedule follow-up reminder if date provided
    if (data.followUpDate) {
      await this.scheduleFollowUpReminder(consultationId, data.followUpDate);
    }

    return updated;
  }

  static async getUpcomingReminders(userId: string) {
    const upcoming = await prisma.consultation.findMany({
      where: {
        OR: [
          { userId },
          { nutritionistId: userId },
        ],
        status: 'SCHEDULED',
        scheduledAt: {
          gte: new Date(),
          lte: addMinutes(new Date(), 24 * 60), // Next 24 hours
        },
      },
      orderBy: { scheduledAt: 'asc' },
      include: {
        user: {
          include: { profile: true },
        },
        nutritionist: {
          include: { profile: true },
        },
      },
    });

    return upcoming;
  }

  private static async scheduleReminders(consultationId: string, scheduledAt: Date) {
    const reminderTimes = [
      { type: 'email', minutesBefore: 24 * 60 }, // 1 day before
      { type: 'email', minutesBefore: 60 }, // 1 hour before
      { type: 'sms', minutesBefore: 30 }, // 30 minutes before
      { type: 'whatsapp', minutesBefore: 15 }, // 15 minutes before
    ];

    const reminders = reminderTimes.map((reminder) => ({
      consultationId,
      type: reminder.type,
      scheduledAt: new Date(scheduledAt.getTime() - reminder.minutesBefore * 60 * 1000),
      status: 'pending',
    }));

    await prisma.consultationReminder.createMany({
      data: reminders,
    });
  }

  private static async cancelReminders(consultationId: string) {
    await prisma.consultationReminder.updateMany({
      where: {
        consultationId,
        status: 'pending',
      },
      data: {
        status: 'cancelled',
      },
    });
  }

  private static async scheduleFollowUpReminder(
    consultationId: string,
    followUpDate: Date
  ) {
    await prisma.consultationReminder.create({
      data: {
        consultationId,
        type: 'email',
        scheduledAt: subHours(followUpDate, 24),
        status: 'pending',
      },
    });
  }

  private static async generatePrescriptionPDF(consultation: any, prescription: any) {
    // This would integrate with a PDF generation service
    // For now, returning a placeholder
    return `prescriptions/${consultation.id}.pdf`;
  }
}
```

### Day 5-7: Calendar & Video Integration

#### 1. Calendar Service
```typescript
// services/consultation/src/services/calendar.service.ts
import { google } from 'googleapis';
import { prisma } from '@nutrition/database';
import { addMinutes, format, startOfDay, endOfDay } from 'date-fns';
import { utcToZonedTime, zonedTimeToUtc } from 'date-fns-tz';

export class CalendarService {
  private static oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URL
  );

  static async getAvailableSlots(
    nutritionistId: string,
    date: Date,
    timezone: string
  ) {
    // Get nutritionist availability
    const nutritionist = await prisma.nutritionistProfile.findUnique({
      where: { userId: nutritionistId },
      include: { user: true },
    });

    if (!nutritionist) {
      throw new Error('Nutritionist not found');
    }

    // Get working hours from availability
    const dayOfWeek = format(date, 'EEEE').toLowerCase();
    const workingHours = nutritionist.availability?.[dayOfWeek] || {
      start: '09:00',
      end: '17:00',
      breaks: [{ start: '13:00', end: '14:00' }],
    };

    // Get existing consultations for the day
    const dayStart = startOfDay(date);
    const dayEnd = endOfDay(date);

    const existingConsultations = await prisma.consultation.findMany({
      where: {
        nutritionistId,
        scheduledAt: {
          gte: dayStart,
          lte: dayEnd,
        },
        status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
      },
      select: {
        scheduledAt: true,
        duration: true,
      },
    });

    // Generate available slots
    const slots = this.generateTimeSlots(
      workingHours,
      existingConsultations,
      date,
      timezone
    );

    return slots;
  }

  static async checkSlotAvailability(
    nutritionistId: string,
    scheduledAt: Date,
    duration: number
  ): Promise<boolean> {
    const endTime = addMinutes(scheduledAt, duration);

    const conflicts = await prisma.consultation.count({
      where: {
        nutritionistId,
        status: { in: ['SCHEDULED', 'IN_PROGRESS'] },
        OR: [
          {
            // New consultation starts during existing one
            scheduledAt: {
              lte: scheduledAt,
            },
            AND: {
              scheduledAt: {
                gt: new Date(scheduledAt.getTime() - duration * 60 * 1000),
              },
            },
          },
          {
            // New consultation ends during existing one
            scheduledAt: {
              lt: endTime,
              gte: scheduledAt,
            },
          },
        ],
      },
    });

    return conflicts === 0;
  }

  static async createEvents(data: {
    consultation: any;
    userTimezone: string;
  }) {
    const { consultation, userTimezone } = data;

    // Create calendar event for user
    if (consultation.user.googleCalendarConnected) {
      await this.createGoogleCalendarEvent({
        userId: consultation.userId,
        title: `Nutrition Consultation with ${consultation.nutritionist.profile?.firstName}`,
        description: `Meeting link: ${consultation.meetingLink}\n\nNotes: ${consultation.notes || 'N/A'}`,
        startTime: consultation.scheduledAt,
        endTime: addMinutes(consultation.scheduledAt, consultation.duration),
        timezone: userTimezone,
      });
    }

    // Create calendar event for nutritionist
    if (consultation.nutritionist.user.googleCalendarConnected) {
      await this.createGoogleCalendarEvent({
        userId: consultation.nutritionistId,
        title: `Consultation with ${consultation.user.profile?.firstName} ${consultation.user.profile?.lastName}`,
        description: `Meeting link: ${consultation.meetingLink}\n\nNotes: ${consultation.notes || 'N/A'}`,
        startTime: consultation.scheduledAt,
        endTime: addMinutes(consultation.scheduledAt, consultation.duration),
        timezone: 'Asia/Kolkata', // Nutritionist timezone
      });
    }
  }

  static async updateEvents(data: {
    consultation: any;
    oldScheduledAt: Date;
  }) {
    // This would update existing calendar events
    // Implementation depends on storing event IDs
  }

  private static generateTimeSlots(
    workingHours: any,
    existingConsultations: any[],
    date: Date,
    timezone: string
  ) {
    const slots: Array<{ time: Date; available: boolean }> = [];
    const slotDuration = 30; // 30-minute slots

    // Parse working hours
    const [startHour, startMinute] = workingHours.start.split(':').map(Number);
    const [endHour, endMinute] = workingHours.end.split(':').map(Number);

    let currentSlot = new Date(date);
    currentSlot.setHours(startHour, startMinute, 0, 0);

    const endTime = new Date(date);
    endTime.setHours(endHour, endMinute, 0, 0);

    while (currentSlot < endTime) {
      // Check if slot is during break time
      const isBreakTime = workingHours.breaks?.some((breakTime: any) => {
        const [breakStartHour, breakStartMinute] = breakTime.start.split(':').map(Number);
        const [breakEndHour, breakEndMinute] = breakTime.end.split(':').map(Number);

        const breakStart = new Date(date);
        breakStart.setHours(breakStartHour, breakStartMinute, 0, 0);

        const breakEnd = new Date(date);
        breakEnd.setHours(breakEndHour, breakEndMinute, 0, 0);

        return currentSlot >= breakStart && currentSlot < breakEnd;
      });

      // Check if slot conflicts with existing consultations
      const hasConflict = existingConsultations.some((consultation) => {
        const consultEnd = addMinutes(consultation.scheduledAt, consultation.duration);
        return currentSlot >= consultation.scheduledAt && currentSlot < consultEnd;
      });

      // Check if slot is in the past
      const isPast = currentSlot < new Date();

      slots.push({
        time: zonedTimeToUtc(currentSlot, timezone),
        available: !isBreakTime && !hasConflict && !isPast,
      });

      currentSlot = addMinutes(currentSlot, slotDuration);
    }

    return slots;
  }

  private static async createGoogleCalendarEvent(data: {
    userId: string;
    title: string;
    description: string;
    startTime: Date;
    endTime: Date;
    timezone: string;
  }) {
    try {
      // Get user's Google tokens
      const tokens = await this.getUserGoogleTokens(data.userId);
      if (!tokens) return;

      this.oauth2Client.setCredentials(tokens);
      const calendar = google.calendar({ version: 'v3', auth: this.oauth2Client });

      const event = {
        summary: data.title,
        description: data.description,
        start: {
          dateTime: data.startTime.toISOString(),
          timeZone: data.timezone,
        },
        end: {
          dateTime: data.endTime.toISOString(),
          timeZone: data.timezone,
        },
        reminders: {
          useDefault: false,
          overrides: [
            { method: 'email', minutes: 60 },
            { method: 'popup', minutes: 15 },
          ],
        },
      };

      await calendar.events.insert({
        calendarId: 'primary',
        requestBody: event,
      });
    } catch (error) {
      console.error('Failed to create Google Calendar event:', error);
    }
  }

  private static async getUserGoogleTokens(userId: string) {
    // This would fetch stored Google OAuth tokens from database
    // Implementation depends on OAuth flow implementation
    return null;
  }
}
```

#### 2. Video Service
```typescript
// services/consultation/src/services/video.service.ts
import axios from 'axios';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

interface CreateMeetingDto {
  consultationId: string;
  topic: string;
  startTime: Date;
  duration: number;
  timezone: string;
}

export class VideoService {
  private static readonly ZOOM_API_URL = 'https://api.zoom.us/v2';
  private static readonly JWT_SECRET = process.env.ZOOM_JWT_SECRET!;
  private static readonly JWT_KEY = process.env.ZOOM_JWT_KEY!;

  static async createMeeting(data: CreateMeetingDto) {
    const token = this.generateZoomJWT();

    try {
      const response = await axios.post(
        `${this.ZOOM_API_URL}/users/me/meetings`,
        {
          topic: data.topic,
          type: 2, // Scheduled meeting
          start_time: data.startTime.toISOString(),
          duration: data.duration,
          timezone: data.timezone,
          password: this.generateMeetingPassword(),
          settings: {
            host_video: true,
            participant_video: true,
            join_before_host: false,
            mute_upon_entry: true,
            watermark: false,
            use_pmi: false,
            approval_type: 0,
            audio: 'both',
            auto_recording: 'cloud',
            waiting_room: true,
          },
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return {
        id: response.data.id.toString(),
        joinUrl: response.data.join_url,
        startUrl: response.data.start_url,
        password: response.data.password,
      };
    } catch (error) {
      console.error('Failed to create Zoom meeting:', error);
      // Fallback to Jitsi Meet
      return this.createJitsiMeeting(data);
    }
  }

  static async updateMeeting(meetingId: string, updates: {
    startTime?: Date;
    duration?: number;
  }) {
    const token = this.generateZoomJWT();

    try {
      await axios.patch(
        `${this.ZOOM_API_URL}/meetings/${meetingId}`,
        {
          start_time: updates.startTime?.toISOString(),
          duration: updates.duration,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );
    } catch (error) {
      console.error('Failed to update Zoom meeting:', error);
    }
  }

  static async cancelMeeting(meetingId: string) {
    const token = this.generateZoomJWT();

    try {
      await axios.delete(
        `${this.ZOOM_API_URL}/meetings/${meetingId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
    } catch (error) {
      console.error('Failed to cancel Zoom meeting:', error);
    }
  }

  static async getHostLink(meetingId: string): Promise<string> {
    // For Zoom, the host link is stored separately
    // For Jitsi, we can generate it with moderator params
    if (meetingId.startsWith('jitsi_')) {
      const roomName = meetingId.replace('jitsi_', '');
      return `https://meet.jit.si/${roomName}#config.prejoinPageEnabled=false&userInfo.displayName=Nutritionist`;
    }

    // For Zoom, return the stored start URL
    return '';
  }

  private static createJitsiMeeting(data: CreateMeetingDto) {
    // Jitsi Meet doesn't require API calls for room creation
    const roomName = `nutrition_${data.consultationId}_${Date.now()}`;
    const joinUrl = `https://meet.jit.si/${roomName}`;

    return {
      id: `jitsi_${roomName}`,
      joinUrl,
      startUrl: joinUrl,
      password: '',
    };
  }

  private static generateZoomJWT(): string {
    const payload = {
      iss: this.JWT_KEY,
      exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour expiry
    };

    return jwt.sign(payload, this.JWT_SECRET);
  }

  private static generateMeetingPassword(): string {
    return crypto.randomBytes(4).toString('hex').substring(0, 6);
  }
}
```

## Week 5: Payment Integration & Security

### Day 1-3: Payment Service Implementation

#### 1. Payment Controller
```typescript
// services/payment/src/controllers/payment.controller.ts
import { Request, Response, NextFunction } from 'express';
import { PaymentService } from '../services/payment.service';
import { InvoiceService } from '../services/invoice.service';
import { AppError } from '../utils/errors';

export class PaymentController {
  static async createOrder(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { 
        amount, 
        currency = 'INR', 
        type, 
        referenceId,
        gateway = 'razorpay' 
      } = req.body;

      const order = await PaymentService.createOrder({
        userId,
        amount,
        currency,
        type,
        referenceId,
        gateway,
      });

      res.json({
        success: true,
        data: order,
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyPayment(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { 
        orderId, 
        paymentId, 
        signature,
        gateway = 'razorpay' 
      } = req.body;

      const payment = await PaymentService.verifyPayment({
        userId,
        orderId,
        paymentId,
        signature,
        gateway,
      });

      res.json({
        success: true,
        message: 'Payment verified successfully',
        data: payment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async handleWebhook(req: Request, res: Response, next: NextFunction) {
    try {
      const signature = req.headers['x-razorpay-signature'] as string;
      const gateway = req.params.gateway;

      await PaymentService.handleWebhook({
        gateway,
        signature,
        payload: req.body,
      });

      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  }

  static async getPaymentHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { status, page = 1, limit = 10 } = req.query;

      const payments = await PaymentService.getPaymentHistory(userId, {
        status: status as string,
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: payments,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getInvoice(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;

      const invoice = await InvoiceService.getInvoice(paymentId, userId);

      res.json({
        success: true,
        data: invoice,
      });
    } catch (error) {
      next(error);
    }
  }

  static async downloadInvoice(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;

      const invoiceBuffer = await InvoiceService.generateInvoicePDF(
        paymentId,
        userId
      );

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="invoice-${paymentId}.pdf"`
      );
      res.send(invoiceBuffer);
    } catch (error) {
      next(error);
    }
  }

  static async initiateRefund(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { paymentId } = req.params;
      const { amount, reason } = req.body;

      const refund = await PaymentService.initiateRefund({
        paymentId,
        userId,
        amount,
        reason,
      });

      res.json({
        success: true,
        message: 'Refund initiated successfully',
        data: refund,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPaymentMethods(req: Request, res: Response, next: NextFunction) {
    try {
      const methods = await PaymentService.getAvailablePaymentMethods();

      res.json({
        success: true,
        data: methods,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Payment Service with Razorpay Integration
```typescript
// services/payment/src/services/payment.service.ts
import Razorpay from 'razorpay';
import crypto from 'crypto';
import { prisma } from '@nutrition/database';
import { PaymentGateway } from './gateways/payment.gateway';
import { RazorpayGateway } from './gateways/razorpay.gateway';
import { CashfreeGateway } from './gateways/cashfree.gateway';
import { generateInvoiceNumber } from '../utils/invoice.utils';

interface CreateOrderDto {
  userId: string;
  amount: number;
  currency: string;
  type: string;
  referenceId: string;
  gateway: string;
}

interface VerifyPaymentDto {
  userId: string;
  orderId: string;
  paymentId: string;
  signature: string;
  gateway: string;
}

export class PaymentService {
  private static gateways: Record<string, PaymentGateway> = {
    razorpay: new RazorpayGateway(),
    cashfree: new CashfreeGateway(),
  };

  static async createOrder(data: CreateOrderDto) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Create order in gateway
    const gatewayOrder = await gateway.createOrder({
      amount: data.amount,
      currency: data.currency,
      receipt: `order_${Date.now()}`,
      notes: {
        userId: data.userId,
        type: data.type,
        referenceId: data.referenceId,
      },
    });

    // Create payment record
    const payment = await prisma.payment.create({
      data: {
        userId: data.userId,
        amount: data.amount,
        currency: data.currency,
        status: 'PENDING',
        gateway: data.gateway,
        gatewayOrderId: gatewayOrder.id,
        metadata: {
          type: data.type,
          referenceId: data.referenceId,
        },
      },
    });

    return {
      paymentId: payment.id,
      orderId: gatewayOrder.id,
      amount: data.amount,
      currency: data.currency,
      gateway: data.gateway,
      gatewayData: gatewayOrder,
    };
  }

  static async verifyPayment(data: VerifyPaymentDto) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Get payment record
    const payment = await prisma.payment.findFirst({
      where: {
        userId: data.userId,
        gatewayOrderId: data.orderId,
        status: 'PENDING',
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    // Verify signature
    const isValid = await gateway.verifySignature({
      orderId: data.orderId,
      paymentId: data.paymentId,
      signature: data.signature,
    });

    if (!isValid) {
      throw new Error('Invalid payment signature');
    }

    // Update payment status
    const updatedPayment = await prisma.payment.update({
      where: { id: payment.id },
      data: {
        status: 'SUCCESS',
        gatewayPaymentId: data.paymentId,
        gatewaySignature: data.signature,
        invoiceNumber: generateInvoiceNumber(),
        updatedAt: new Date(),
      },
    });

    // Handle post-payment actions based on type
    await this.handlePostPaymentActions(updatedPayment);

    return updatedPayment;
  }

  static async handleWebhook(data: {
    gateway: string;
    signature: string;
    payload: any;
  }) {
    const gateway = this.gateways[data.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Verify webhook signature
    const isValid = await gateway.verifyWebhookSignature(
      data.payload,
      data.signature
    );

    if (!isValid) {
      throw new Error('Invalid webhook signature');
    }

    // Process webhook based on event type
    const event = gateway.parseWebhookEvent(data.payload);

    switch (event.type) {
      case 'payment.captured':
        await this.handlePaymentCaptured(event.data);
        break;
      case 'payment.failed':
        await this.handlePaymentFailed(event.data);
        break;
      case 'refund.processed':
        await this.handleRefundProcessed(event.data);
        break;
      default:
        console.log('Unhandled webhook event:', event.type);
    }
  }

  static async getPaymentHistory(userId: string, options: {
    status?: string;
    page: number;
    limit: number;
  }) {
    const where: any = { userId };

    if (options.status) {
      where.status = options.status;
    }

    const [payments, total] = await Promise.all([
      prisma.payment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          consultation: {
            include: {
              nutritionist: {
                include: { profile: true },
              },
            },
          },
          journey: {
            include: { program: true },
          },
        },
      }),
      prisma.payment.count({ where }),
    ]);

    return {
      payments,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async initiateRefund(data: {
    paymentId: string;
    userId: string;
    amount?: number;
    reason: string;
  }) {
    const payment = await prisma.payment.findFirst({
      where: {
        id: data.paymentId,
        userId: data.userId,
        status: 'SUCCESS',
      },
    });

    if (!payment) {
      throw new Error('Payment not found or not eligible for refund');
    }

    // Check if already refunded
    if (payment.refundId) {
      throw new Error('Payment already refunded');
    }

    const gateway = this.gateways[payment.gateway];
    if (!gateway) {
      throw new Error('Invalid payment gateway');
    }

    // Initiate refund with gateway
    const refundAmount = data.amount || payment.amount;
    const refund = await gateway.initiateRefund({
      paymentId: payment.gatewayPaymentId!,
      amount: refundAmount,
      notes: {
        reason: data.reason,
      },
    });

    // Update payment record
    await prisma.payment.update({
      where: { id: payment.id },
      data: {
        refundId: refund.id,
        refundAmount: refundAmount,
        refundedAt: new Date(),
        status: refundAmount === payment.amount ? 'REFUNDED' : 'PARTIALLY_REFUNDED',
      },
    });

    return refund;
  }

  static async getAvailablePaymentMethods() {
    return [
      {
        id: 'upi',
        name: 'UPI',
        description: 'Pay using any UPI app',
        icon: 'upi-icon',
        enabled: true,
      },
      {
        id: 'card',
        name: 'Credit/Debit Card',
        description: 'All major cards accepted',
        icon: 'card-icon',
        enabled: true,
      },
      {
        id: 'netbanking',
        name: 'Net Banking',
        description: 'All major banks supported',
        icon: 'bank-icon',
        enabled: true,
      },
      {
        id: 'wallet',
        name: 'Wallet',
        description: 'Paytm, PhonePe, etc.',
        icon: 'wallet-icon',
        enabled: true,
      },
    ];
  }

  private static async handlePostPaymentActions(payment: any) {
    const metadata = payment.metadata as any;

    switch (metadata.type) {
      case 'consultation':
        await this.activateConsultation(metadata.referenceId);
        break;
      case 'program':
        await this.activateProgramEnrollment(payment.userId, metadata.referenceId);
        break;
      case 'subscription':
        await this.activateSubscription(payment.userId, metadata.referenceId);
        break;
    }

    // Send payment confirmation
    await this.sendPaymentConfirmation(payment);
  }

  private static async handlePaymentCaptured(data: any) {
    await prisma.payment.update({
      where: { gatewayPaymentId: data.id },
      data: {
        status: 'SUCCESS',
        paymentMethod: data.method,
      },
    });
  }

  private static async handlePaymentFailed(data: any) {
    await prisma.payment.update({
      where: { gatewayPaymentId: data.id },
      data: {
        status: 'FAILED',
        failureReason: data.error?.description,
      },
    });
  }

  private static async handleRefundProcessed(data: any) {
    await prisma.payment.update({
      where: { refundId: data.id },
      data: {
        status: data.amount === data.payment_amount ? 'REFUNDED' : 'PARTIALLY_REFUNDED',
      },
    });
  }

  private static async activateConsultation(consultationId: string) {
    // Implementation for activating consultation after payment
  }

  private static async activateProgramEnrollment(userId: string, programId: string) {
    // Implementation for activating program enrollment
  }

  private static async activateSubscription(userId: string, planId: string) {
    // Implementation for activating subscription
  }

  private static async sendPaymentConfirmation(payment: any) {
    // Send email confirmation
  }
}
```

#### 3. Razorpay Gateway Implementation
```typescript
// services/payment/src/services/gateways/razorpay.gateway.ts
import Razorpay from 'razorpay';
import crypto from 'crypto';
import { PaymentGateway } from './payment.gateway';

export class RazorpayGateway implements PaymentGateway {
  private razorpay: Razorpay;

  constructor() {
    this.razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID!,
      key_secret: process.env.RAZORPAY_KEY_SECRET!,
    });
  }

  async createOrder(data: {
    amount: number;
    currency: string;
    receipt: string;
    notes?: any;
  }) {
    const order = await this.razorpay.orders.create({
      amount: Math.round(data.amount * 100), // Convert to paise
      currency: data.currency,
      receipt: data.receipt,
      notes: data.notes,
    });

    return {
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      status: order.status,
    };
  }

  async verifySignature(data: {
    orderId: string;
    paymentId: string;
    signature: string;
  }): Promise<boolean> {
    const text = `${data.orderId}|${data.paymentId}`;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET!)
      .update(text)
      .digest('hex');

    return expectedSignature === data.signature;
  }

  async verifyWebhookSignature(payload: any, signature: string): Promise<boolean> {
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET!)
      .update(JSON.stringify(payload))
      .digest('hex');

    return expectedSignature === signature;
  }

  parseWebhookEvent(payload: any) {
    return {
      type: payload.event,
      data: payload.payload.payment?.entity || payload.payload.refund?.entity,
    };
  }

  async initiateRefund(data: {
    paymentId: string;
    amount: number;
    notes?: any;
  }) {
    const refund = await this.razorpay.payments.refund(data.paymentId, {
      amount: Math.round(data.amount * 100),
      notes: data.notes,
    });

    return {
      id: refund.id,
      amount: refund.amount,
      status: refund.status,
    };
  }

  async fetchPayment(paymentId: string) {
    return this.razorpay.payments.fetch(paymentId);
  }
}
```

### Day 4-5: Invoice Generation

#### 1. Invoice Service
```typescript
// services/payment/src/services/invoice.service.ts
import PDFDocument from 'pdfkit';
import { prisma } from '@nutrition/database';
import { uploadToStorage } from '../utils/storage';
import { formatCurrency, formatDate } from '../utils/format.utils';

export class InvoiceService {
  static async generateInvoice(paymentId: string) {
    const payment = await prisma.payment.findUnique({
      where: { id: paymentId },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    // Generate PDF
    const pdfBuffer = await this.createInvoicePDF(payment);

    // Upload to storage
    const filename = `invoices/${payment.invoiceNumber}.pdf`;
    const invoiceUrl = await uploadToStorage(pdfBuffer, filename, 'application/pdf');

    // Update payment with invoice URL
    await prisma.payment.update({
      where: { id: paymentId },
      data: { invoiceUrl },
    });

    return invoiceUrl;
  }

  static async getInvoice(paymentId: string, userId: string) {
    const payment = await prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId,
        status: 'SUCCESS',
      },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Invoice not found');
    }

    return {
      invoiceNumber: payment.invoiceNumber,
      invoiceUrl: payment.invoiceUrl,
      payment,
    };
  }

  static async generateInvoicePDF(paymentId: string, userId: string): Promise<Buffer> {
    const payment = await prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId,
        status: 'SUCCESS',
      },
      include: {
        user: {
          include: { profile: true },
        },
        consultation: {
          include: {
            nutritionist: {
              include: { profile: true },
            },
          },
        },
        journey: {
          include: { program: true },
        },
      },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    return this.createInvoicePDF(payment);
  }

  private static async createInvoicePDF(payment: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 50 });
      const buffers: Buffer[] = [];

      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', reject);

      // Header
      doc
        .fontSize(24)
        .text('INVOICE', 50, 50)
        .fontSize(10)
        .text(`Invoice Number: ${payment.invoiceNumber}`, 50, 80)
        .text(`Date: ${formatDate(payment.createdAt)}`, 50, 95);

      // Company Details
      doc
        .fontSize(16)
        .text('Nutrition Platform', 300, 50)
        .fontSize(10)
        .text('123 Health Street', 300, 75)
        .text('Mumbai, MH 400001', 300, 90)
        .text('GSTIN: 27AAAAA0000A1Z5', 300, 105);

      // Bill To
      doc
        .fontSize(12)
        .text('Bill To:', 50, 150)
        .fontSize(10)
        .text(
          `${payment.user.profile?.firstName} ${payment.user.profile?.lastName}`,
          50,
          170
        )
        .text(payment.user.email, 50, 185)
        .text(payment.user.phone || '', 50, 200);

      // Line Items
      doc.moveTo(50, 250).lineTo(550, 250).stroke();

      doc
        .fontSize(12)
        .text('Description', 50, 260)
        .text('Amount', 450, 260, { align: 'right' });

      doc.moveTo(50, 280).lineTo(550, 280).stroke();

      // Item details
      let description = '';
      if (payment.consultation) {
        description = `Consultation with ${payment.consultation.nutritionist.profile?.firstName} ${payment.consultation.nutritionist.profile?.lastName}`;
      } else if (payment.journey) {
        description = `${payment.journey.program.name} Program`;
      }

      doc
        .fontSize(10)
        .text(description, 50, 290)
        .text(formatCurrency(payment.amount, payment.currency), 450, 290, {
          align: 'right',
        });

      // GST Calculation
      const gstRate = 0.18; // 18% GST
      const baseAmount = payment.amount / (1 + gstRate);
      const gstAmount = payment.amount - baseAmount;

      doc
        .text('Subtotal', 350, 330)
        .text(formatCurrency(baseAmount, payment.currency), 450, 330, {
          align: 'right',
        })
        .text('GST (18%)', 350, 350)
        .text(formatCurrency(gstAmount, payment.currency), 450, 350, {
          align: 'right',
        });

      doc.moveTo(350, 370).lineTo(550, 370).stroke();

      doc
        .fontSize(12)
        .text('Total', 350, 380)
        .text(formatCurrency(payment.amount, payment.currency), 450, 380, {
          align: 'right',
        });

      // Payment Details
      doc
        .fontSize(10)
        .text('Payment Details:', 50, 450)
        .text(`Payment ID: ${payment.gatewayPaymentId}`, 50, 470)
        .text(`Payment Method: ${payment.paymentMethod || 'Online'}`, 50, 485)
        .text(`Status: ${payment.status}`, 50, 500);

      // Footer
      doc
        .fontSize(8)
        .text(
          'This is a computer-generated invoice and does not require a signature.',
          50,
          700,
          { align: 'center' }
        );

      doc.end();
    });
  }
}
```

### Day 6-7: Security Implementation

#### 1. Security Middleware
```typescript
// packages/security/src/middleware/security.middleware.ts
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://www.google-analytics.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.razorpay.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'self'", 'https://api.razorpay.com'],
    },
  },
  crossOriginEmbedderPolicy: false,
});

export const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true,
});

export const uploadRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Upload limit exceeded, please try again later.',
});

export const sanitizeInput = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized ${key} in request from ${req.ip}`);
  },
});

export const preventParamPollution = hpp({
  whitelist: ['sort', 'fields', 'page', 'limit'],
});

export const generateCSRFToken = (req: Request, res: Response, next: NextFunction) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
};

export const validateCSRFToken = (req: Request, res: Response, next: NextFunction) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const token = req.body._csrf || req.headers['x-csrf-token'];
  
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({
      success: false,
      error: 'Invalid CSRF token',
    });
  }

  next();
};

export const validateInput = (schema: any) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map((detail: any) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return res.status(400).json({
        success: false,
        errors,
      });
    }

    next();
  };
};

export const encryptSensitiveData = (data: any, fields: string[]) => {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  
  const encrypted = { ...data };

  fields.forEach((field) => {
    if (data[field]) {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      
      let encryptedData = cipher.update(data[field], 'utf8', 'hex');
      encryptedData += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      encrypted[field] = {
        data: encryptedData,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
      };
    }
  });

  return encrypted;
};

export const decryptSensitiveData = (data: any, fields: string[]) => {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  
  const decrypted = { ...data };

  fields.forEach((field) => {
    if (data[field] && typeof data[field] === 'object') {
      const { data: encryptedData, iv, authTag } = data[field];
      
      const decipher = crypto.createDecipheriv(
        algorithm,
        key,
        Buffer.from(iv, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
      decryptedData += decipher.final('utf8');
      
      decrypted[field] = decryptedData;
    }
  });

  return decrypted;
};
```

#### 2. API Security Service
```typescript
// packages/security/src/services/api-security.service.ts
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { prisma } from '@nutrition/database';

export class APISecurityService {
  private static readonly API_KEY_PREFIX = 'ntp_';
  private static readonly WEBHOOK_TOLERANCE = 300; // 5 minutes

  static async generateAPIKey(userId: string, name: string): Promise<string> {
    const key = `${this.API_KEY_PREFIX}${crypto.randomBytes(32).toString('hex')}`;
    const hashedKey = this.hashAPIKey(key);

    await prisma.apiKey.create({
      data: {
        userId,
        name,
        key: hashedKey,
        lastUsedAt: null,
      },
    });

    return key;
  }

  static async validateAPIKey(key: string): Promise<boolean> {
    if (!key.startsWith(this.API_KEY_PREFIX)) {
      return false;
    }

    const hashedKey = this.hashAPIKey(key);
    
    const apiKey = await prisma.apiKey.findUnique({
      where: { key: hashedKey },
      include: { user: true },
    });

    if (!apiKey || !apiKey.isActive) {
      return false;
    }

    // Update last used
    await prisma.apiKey.update({
      where: { id: apiKey.id },
      data: { lastUsedAt: new Date() },
    });

    return true;
  }

  static validateWebhookSignature(
    payload: string,
    signature: string,
    secret: string,
    timestamp?: number
  ): boolean {
    // Check timestamp to prevent replay attacks
    if (timestamp) {
      const currentTime = Math.floor(Date.now() / 1000);
      if (Math.abs(currentTime - timestamp) > this.WEBHOOK_TOLERANCE) {
        return false;
      }
    }

    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(timestamp ? `${timestamp}.${payload}` : payload)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  static generateRequestSignature(
    method: string,
    path: string,
    body: any,
    timestamp: number,
    secret: string
  ): string {
    const payload = `${method.toUpperCase()}${path}${JSON.stringify(body)}${timestamp}`;
    
    return crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');
  }

  static validateRequestSignature(req: Request, secret: string): boolean {
    const signature = req.headers['x-signature'] as string;
    const timestamp = parseInt(req.headers['x-timestamp'] as string);

    if (!signature || !timestamp) {
      return false;
    }

    const expectedSignature = this.generateRequestSignature(
      req.method,
      req.path,
      req.body,
      timestamp,
      secret
    );

    return this.validateWebhookSignature(
      JSON.stringify(req.body),
      signature,
      secret,
      timestamp
    );
  }

  static encryptAPIResponse(data: any, key: string): string {
    const algorithm = 'aes-256-cbc';
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);

    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return iv.toString('hex') + ':' + encrypted;
  }

  static decryptAPIRequest(encryptedData: string, key: string): any {
    const [ivHex, encrypted] = encryptedData.split(':');
    const algorithm = 'aes-256-cbc';
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  }

  private static hashAPIKey(key: string): string {
    return crypto
      .createHash('sha256')
      .update(key)
      .digest('hex');
  }

  static async logAPIAccess(req: Request, apiKeyId: string) {
    await prisma.apiAccessLog.create({
      data: {
        apiKeyId,
        method: req.method,
        path: req.path,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        statusCode: 200, // Will be updated by response interceptor
        responseTime: 0, // Will be updated by response interceptor
      },
    });
  }

  static generateJWT(payload: any, expiresIn: string = '1h'): string {
    return jwt.sign(payload, process.env.JWT_SECRET!, {
      expiresIn,
      algorithm: 'HS256',
    });
  }

  static verifyJWT(token: string): any {
    return jwt.verify(token, process.env.JWT_SECRET!);
  }
}
```

## Week 6: Quiz Engine & Recommendation System

### Day 1-3: Quiz Service Implementation

#### 1. Quiz Controller
```typescript
// services/quiz/src/controllers/quiz.controller.ts
import { Request, Response, NextFunction } from 'express';
import { QuizService } from '../services/quiz.service';
import { RecommendationService } from '../services/recommendation.service';
import { AppError } from '../utils/errors';

export class QuizController {
  static async getQuizByType(req: Request, res: Response, next: NextFunction) {
    try {
      const { type } = req.params;
      const userId = req.user?.userId;

      const quiz = await QuizService.getQuizByType(type);

      if (!quiz) {
        throw new AppError('Quiz not found', 404);
      }

      // Get previous results if user is authenticated
      let previousResult = null;
      if (userId) {
        previousResult = await QuizService.getLatestResult(userId, type);
      }

      res.json({
        success: true,
        data: {
          quiz,
          previousResult,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async submitQuiz(req: Request, res: Response, next: NextFunction) {
    try {
      const { type } = req.params;
      const { responses } = req.body;
      const userId = req.user?.userId;

      // Validate responses
      const validation = await QuizService.validateResponses(type, responses);
      if (!validation.valid) {
        throw new AppError('Invalid responses', 400, validation.errors);
      }

      // Process quiz
      const result = await QuizService.processQuizSubmission({
        quizType: type,
        responses,
        userId,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });

      // Generate recommendations
      const recommendations = await RecommendationService.generateRecommendations(
        result
      );

      res.json({
        success: true,
        data: {
          result,
          recommendations,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizResults(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { page = 1, limit = 10 } = req.query;

      const results = await QuizService.getUserQuizResults(userId, {
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: results,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizResult(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const result = await QuizService.getQuizResult(id, userId);

      if (!result) {
        throw new AppError('Quiz result not found', 404);
      }

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getQuizAnalytics(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const analytics = await QuizService.getUserQuizAnalytics(userId);

      res.json({
        success: true,
        data: analytics,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Quiz Service
```typescript
// services/quiz/src/services/quiz.service.ts
import { prisma } from '@nutrition/database';
import { QuizEngine } from '../engines/quiz.engine';
import { SymptomQuizEngine } from '../engines/symptom.quiz.engine';
import { GutHealthQuizEngine } from '../engines/gut-health.quiz.engine';
import { StressQuizEngine } from '../engines/stress.quiz.engine';

interface QuizSubmission {
  quizType: string;
  responses: Record<string, any>;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export class QuizService {
  private static engines: Record<string, QuizEngine> = {
    symptom: new SymptomQuizEngine(),
    gut_health: new GutHealthQuizEngine(),
    stress: new StressQuizEngine(),
  };

  static async getQuizByType(type: string) {
    const quiz = await prisma.quiz.findFirst({
      where: {
        type: type.toUpperCase(),
        isActive: true,
      },
    });

    if (!quiz) {
      return null;
    }

    // Parse questions and add frontend-friendly structure
    const questions = quiz.questions as any[];
    const formattedQuestions = questions.map((q, index) => ({
      id: q.id || `q${index + 1}`,
      text: q.text,
      type: q.type || 'single_choice',
      required: q.required !== false,
      options: q.options || [],
      validation: q.validation || {},
      conditionalLogic: q.conditionalLogic || null,
    }));

    return {
      ...quiz,
      questions: formattedQuestions,
      estimatedTime: this.calculateEstimatedTime(formattedQuestions),
    };
  }

  static async validateResponses(
    quizType: string,
    responses: Record<string, any>
  ) {
    const quiz = await this.getQuizByType(quizType);
    if (!quiz) {
      return { valid: false, errors: ['Quiz not found'] };
    }

    const errors: string[] = [];
    const questions = quiz.questions as any[];

    for (const question of questions) {
      const response = responses[question.id];

      // Check required fields
      if (question.required && !response) {
        errors.push(`Question "${question.text}" is required`);
        continue;
      }

      // Validate response type
      if (response) {
        switch (question.type) {
          case 'single_choice':
            if (!question.options.find((opt: any) => opt.value === response)) {
              errors.push(`Invalid response for "${question.text}"`);
            }
            break;
          case 'multiple_choice':
            if (!Array.isArray(response)) {
              errors.push(`"${question.text}" requires multiple selections`);
            }
            break;
          case 'scale':
            const value = Number(response);
            if (isNaN(value) || value < 1 || value > 10) {
              errors.push(`"${question.text}" must be between 1 and 10`);
            }
            break;
          case 'text':
            if (question.validation?.maxLength && response.length > question.validation.maxLength) {
              errors.push(`"${question.text}" exceeds maximum length`);
            }
            break;
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static async processQuizSubmission(submission: QuizSubmission) {
    const quiz = await prisma.quiz.findFirst({
      where: {
        type: submission.quizType.toUpperCase(),
        isActive: true,
      },
    });

    if (!quiz) {
      throw new Error('Quiz not found');
    }

    // Get the appropriate engine
    const engine = this.engines[submission.quizType.toLowerCase()];
    if (!engine) {
      throw new Error('Quiz engine not found');
    }

    // Calculate score and analysis
    const { score, analysis, riskFactors } = await engine.processResponses(
      submission.responses,
      quiz.scoring as any
    );

    // Save quiz result
    const result = await prisma.quizResult.create({
      data: {
        userId: submission.userId,
        quizId: quiz.id,
        quizType: quiz.type,
        responses: submission.responses,
        score,
        analysis,
        recommendations: await engine.generateRecommendations(score, analysis),
        ipAddress: submission.ipAddress,
        userAgent: submission.userAgent,
      },
    });

    // If user is authenticated, update their profile with insights
    if (submission.userId) {
      await this.updateUserInsights(submission.userId, quiz.type, analysis);
    }

    return result;
  }

  static async getLatestResult(userId: string, quizType: string) {
    return prisma.quizResult.findFirst({
      where: {
        userId,
        quizType: quizType.toUpperCase(),
      },
      orderBy: { completedAt: 'desc' },
    });
  }

  static async getUserQuizResults(userId: string, options: {
    page: number;
    limit: number;
  }) {
    const [results, total] = await Promise.all([
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          quiz: true,
        },
      }),
      prisma.quizResult.count({ where: { userId } }),
    ]);

    return {
      results,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getQuizResult(resultId: string, userId?: string) {
    const where: any = { id: resultId };
    
    // If userId is provided, ensure the result belongs to them
    if (userId) {
      where.userId = userId;
    }

    return prisma.quizResult.findFirst({
      where,
      include: {
        quiz: true,
      },
    });
  }

  static async getUserQuizAnalytics(userId: string) {
    const results = await prisma.quizResult.findMany({
      where: { userId },
      orderBy: { completedAt: 'asc' },
    });

    const analytics = {
      totalQuizzesTaken: results.length,
      quizzesByType: {} as Record<string, number>,
      progressOverTime: {} as Record<string, any[]>,
      latestInsights: {} as Record<string, any>,
    };

    // Group by quiz type
    results.forEach((result) => {
      const type = result.quizType;
      analytics.quizzesByType[type] = (analytics.quizzesByType[type] || 0) + 1;

      if (!analytics.progressOverTime[type]) {
        analytics.progressOverTime[type] = [];
      }

      analytics.progressOverTime[type].push({
        date: result.completedAt,
        score: result.score,
        insights: result.analysis,
      });

      // Keep latest insights
      if (!analytics.latestInsights[type] || 
          result.completedAt > analytics.latestInsights[type].date) {
        analytics.latestInsights[type] = {
          date: result.completedAt,
          analysis: result.analysis,
          recommendations: result.recommendations,
        };
      }
    });

    return analytics;
  }

  private static calculateEstimatedTime(questions: any[]): number {
    // Estimate based on question types
    let totalSeconds = 0;

    questions.forEach((question) => {
      switch (question.type) {
        case 'single_choice':
          totalSeconds += 10;
          break;
        case 'multiple_choice':
          totalSeconds += 15;
          break;
        case 'scale':
          totalSeconds += 8;
          break;
        case 'text':
          totalSeconds += 30;
          break;
        default:
          totalSeconds += 10;
      }
    });

    return Math.ceil(totalSeconds / 60); // Return in minutes
  }

  private static async updateUserInsights(
    userId: string,
    quizType: string,
    analysis: any
  ) {
    const profile = await prisma.userProfile.findUnique({
      where: { userId },
    });

    if (!profile) {
      return;
    }

    const currentInsights = profile.preferences?.healthInsights || {};
    currentInsights[quizType.toLowerCase()] = {
      ...analysis,
      updatedAt: new Date(),
    };

    await prisma.userProfile.update({
      where: { userId },
      data: {
        preferences: {
          ...profile.preferences,
          healthInsights: currentInsights,
        },
      },
    });
  }
}
```

#### 3. Quiz Engine Implementation
```typescript
// services/quiz/src/engines/symptom.quiz.engine.ts
import { QuizEngine } from './quiz.engine';

export class SymptomQuizEngine implements QuizEngine {
  async processResponses(responses: Record<string, any>, scoring: any) {
    let totalScore = 0;
    const categoryScores: Record<string, number> = {
      digestive: 0,
      energy: 0,
      mental: 0,
      hormonal: 0,
      immune: 0,
    };

    const riskFactors: string[] = [];

    // Process each response
    Object.entries(responses).forEach(([questionId, response]) => {
      const questionScoring = scoring[questionId];
      if (!questionScoring) return;

      // Calculate score based on response
      let questionScore = 0;
      if (typeof response === 'number') {
        questionScore = response;
      } else if (questionScoring.options?.[response]) {
        questionScore = questionScoring.options[response];
      }

      totalScore += questionScore;

      // Add to category scores
      if (questionScoring.category) {
        categoryScores[questionScoring.category] += questionScore;
      }

      // Check for risk factors
      if (questionScore >= 7) {
        riskFactors.push(questionScoring.riskMessage || questionId);
      }
    });

    // Analyze results
    const analysis = this.analyzeResults(totalScore, categoryScores, riskFactors);

    return {
      score: totalScore,
      analysis,
      riskFactors,
    };
  }

  private analyzeResults(
    totalScore: number,
    categoryScores: Record<string, number>,
    riskFactors: string[]
  ) {
    const maxPossibleScore = 100; // Adjust based on actual quiz
    const percentage = (totalScore / maxPossibleScore) * 100;

    let severity = 'low';
    let primaryConcern = '';
    let secondaryConcerns: string[] = [];

    // Determine severity
    if (percentage >= 70) {
      severity = 'high';
    } else if (percentage >= 40) {
      severity = 'moderate';
    }

    // Find primary concern
    const sortedCategories = Object.entries(categoryScores)
      .sort(([, a], [, b]) => b - a);

    if (sortedCategories.length > 0) {
      primaryConcern = sortedCategories[0][0];
      secondaryConcerns = sortedCategories
        .slice(1, 3)
        .filter(([, score]) => score > 0)
        .map(([category]) => category);
    }

    return {
      severity,
      percentage,
      primaryConcern,
      secondaryConcerns,
      categoryBreakdown: categoryScores,
      interpretation: this.getInterpretation(severity, primaryConcern),
    };
  }

  private getInterpretation(severity: string, primaryConcern: string): string {
    const interpretations: Record<string, Record<string, string>> = {
      low: {
        digestive: 'Your digestive health appears to be in good shape. Continue with your current healthy habits.',
        energy: 'Your energy levels seem stable. Maintain your current lifestyle practices.',
        mental: 'Your mental wellness indicators are positive. Keep up the good work!',
        hormonal: 'Your hormonal balance appears healthy. Continue monitoring for any changes.',
        immune: 'Your immune system seems to be functioning well. Keep supporting it with good nutrition.',
      },
      moderate: {
        digestive: 'You may be experiencing some digestive issues. Consider dietary adjustments and stress management.',
        energy: 'Your energy levels could use some support. Focus on sleep quality and balanced nutrition.',
        mental: 'Some stress or mood concerns noted. Consider mindfulness practices and adequate rest.',
        hormonal: 'Some hormonal imbalance indicators present. A targeted nutrition plan may help.',
        immune: 'Your immune system may need extra support. Focus on nutrient-dense foods and rest.',
      },
      high: {
        digestive: 'Significant digestive concerns identified. Professional guidance is recommended.',
        energy: 'Severe fatigue or energy issues detected. Consult with a healthcare provider.',
        mental: 'High stress or mood concerns present. Professional support may be beneficial.',
        hormonal: 'Significant hormonal imbalance indicators. Medical evaluation recommended.',
        immune: 'Your immune system appears compromised. Seek professional health guidance.',
      },
    };

    return interpretations[severity]?.[primaryConcern] || 
           'Based on your responses, a personalized consultation would be beneficial.';
  }

  async generateRecommendations(score: number, analysis: any) {
    const recommendations: any[] = [];

    // Program recommendations based on primary concern
    const programMap: Record<string, string> = {
      digestive: 'GUT_HEALTH',
      energy: 'METABOLIC_RESET',
      hormonal: 'PCOS_RESTORE',
      mental: 'STRESS_MANAGEMENT',
      immune: 'DETOX_HORMONE',
    };

    if (analysis.primaryConcern && programMap[analysis.primaryConcern]) {
      recommendations.push({
        type: 'program',
        priority: 'high',
        programType: programMap[analysis.primaryConcern],
        message: `Based on your ${analysis.primaryConcern} concerns, our ${programMap[analysis.primaryConcern].replace('_', ' ')} program may be ideal for you.`,
      });
    }

    // Lifestyle recommendations
    if (analysis.severity === 'moderate' || analysis.severity === 'high') {
      recommendations.push({
        type: 'consultation',
        priority: analysis.severity === 'high' ? 'urgent' : 'medium',
        message: 'A personalized consultation can help address your specific health concerns.',
      });
    }

    // Category-specific recommendations
    Object.entries(analysis.categoryBreakdown).forEach(([category, score]) => {
      if (score > 5) {
        recommendations.push(...this.getCategoryRecommendations(category, score));
      }
    });

    return recommendations;
  }

  private getCategoryRecommendations(category: string, score: number): any[] {
    const recommendations: Record<string, any[]> = {
      digestive: [
        {
          type: 'lifestyle',
          title: 'Improve Gut Health',
          suggestions: [
            'Include fermented foods daily',
            'Increase fiber intake gradually',
            'Stay hydrated with 8-10 glasses of water',
            'Consider a food sensitivity test',
          ],
        },
        {
          type: 'resource',
          title: '7-Day Gut Reset Guide',
          resourceId: 'gut-reset-guide',
        },
      ],
      energy: [
        {
          type: 'lifestyle',
          title: 'Boost Energy Naturally',
          suggestions: [
            'Prioritize 7-8 hours of quality sleep',
            'Balance blood sugar with protein at each meal',
            'Consider B-vitamin supplementation',
            'Reduce caffeine dependency',
          ],
        },
        {
          type: 'calculator',
          title: 'Calculate Your Ideal Macros',
          toolId: 'macro-calculator',
        },
      ],
      // ... other categories
    };

    return recommendations[category] || [];
  }
}
```

### Day 4-7: Recommendation Engine

#### 1. Recommendation Service
```typescript
// services/quiz/src/services/recommendation.service.ts
import { prisma } from '@nutrition/database';
import { MachineLearningService } from './ml.service';
import { ContentBasedFilter } from '../algorithms/content-based.filter';
import { CollaborativeFilter } from '../algorithms/collaborative.filter';

export class RecommendationService {
  static async generateRecommendations(quizResult: any) {
    const userId = quizResult.userId;
    const analysis = quizResult.analysis;

    // Get user history if authenticated
    let userHistory = null;
    if (userId) {
      userHistory = await this.getUserHistory(userId);
    }

    // Generate different types of recommendations
    const [
      programRecommendations,
      contentRecommendations,
      nutritionistRecommendations,
      resourceRecommendations,
    ] = await Promise.all([
      this.recommendPrograms(analysis, userHistory),
      this.recommendContent(analysis, userHistory),
      this.recommendNutritionists(analysis, userId),
      this.recommendResources(analysis),
    ]);

    // Combine and prioritize recommendations
    const combinedRecommendations = this.prioritizeRecommendations({
      programs: programRecommendations,
      content: contentRecommendations,
      nutritionists: nutritionistRecommendations,
      resources: resourceRecommendations,
    });

    // Track recommendations for analytics
    if (userId) {
      await this.trackRecommendations(userId, combinedRecommendations);
    }

    return combinedRecommendations;
  }

  private static async recommendPrograms(analysis: any, userHistory: any) {
    // Get all active programs
    const programs = await prisma.program.findMany({
      where: { isActive: true },
      include: {
        reviews: {
          select: { rating: true },
        },
      },
    });

    // Score programs based on analysis
    const scoredPrograms = programs.map((program) => {
      let score = 0;

      // Match program type with primary concern
      if (this.matchProgramToConcern(program.type, analysis.primaryConcern)) {
        score += 50;
      }

      // Consider secondary concerns
      analysis.secondaryConcerns.forEach((concern: string) => {
        if (this.matchProgramToConcern(program.type, concern)) {
          score += 20;
        }
      });

      // Factor in program ratings
      const avgRating = program.reviews.length > 0
        ? program.reviews.reduce((sum, r) => sum + r.rating, 0) / program.reviews.length
        : 3;
      score += avgRating * 10;

      // User history considerations
      if (userHistory) {
        // Avoid recommending completed programs
        if (userHistory.completedPrograms.includes(program.id)) {
          score -= 100;
        }
        // Boost programs similar to previously successful ones
        if (userHistory.successfulPrograms.includes(program.type)) {
          score += 30;
        }
      }

      return { ...program, score };
    });

    // Sort and return top programs
    return scoredPrograms
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(({ score, ...program }) => ({
        ...program,
        reason: this.generateProgramReason(program, analysis),
        confidence: Math.min(score / 100, 1),
      }));
  }

  private static async recommendContent(analysis: any, userHistory: any) {
    // Use content-based filtering
    const contentFilter = new ContentBasedFilter();
    
    // Get user interests from analysis
    const interests = this.extractInterestsFromAnalysis(analysis);

    // Get relevant blog posts
    const blogPosts = await prisma.blogPost.findMany({
      where: {
        isPublished: true,
        OR: interests.map((interest) => ({
          tags: { has: interest },
        })),
      },
      orderBy: { publishedAt: 'desc' },
      take: 20,
    });

    // Score and filter content
    const scoredContent = await contentFilter.scoreContent(
      blogPosts,
      interests,
      userHistory
    );

    return scoredContent.slice(0, 5);
  }

  private static async recommendNutritionists(analysis: any, userId?: string) {
    const nutritionists = await prisma.nutritionistProfile.findMany({
      where: { isActive: true },
      include: {
        user: {
          include: { profile: true },
        },
      },
    });

    // Score nutritionists based on specialization match
    const scored = nutritionists.map((nutritionist) => {
      let score = 0;

      // Match specializations with concerns
      const relevantSpecs = this.getRelevantSpecializations(analysis);
      relevantSpecs.forEach((spec) => {
        if (nutritionist.specializations.includes(spec)) {
          score += 30;
        }
      });

      // Consider ratings
      score += nutritionist.rating * 10;

      // Language preferences
      if (userId) {
        // Would check user's language preference
        score += 10;
      }

      return { ...nutritionist, score };
    });

    return scored
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(({ score, ...nutritionist }) => ({
        ...nutritionist,
        matchPercentage: Math.min((score / 100) * 100, 95),
      }));
  }

  private static async recommendResources(analysis: any) {
    const resourceTypes = this.getRelevantResourceTypes(analysis);

    const resources = await prisma.resource.findMany({
      where: {
        type: { in: resourceTypes },
        isPublic: true,
      },
      orderBy: { downloadCount: 'desc' },
      take: 10,
    });

    // Filter based on analysis
    return resources.filter((resource) => {
      const tags = resource.tags || [];
      return tags.some((tag) => 
        this.isTagRelevant(tag, analysis)
      );
    }).slice(0, 3);
  }

  private static prioritizeRecommendations(recommendations: any) {
    const prioritized: any[] = [];

    // High priority: Urgent health concerns
    if (recommendations.programs.some((p: any) => p.confidence > 0.8)) {
      prioritized.push({
        type: 'action',
        priority: 'high',
        title: 'Recommended Program',
        item: recommendations.programs[0],
        cta: 'Learn More',
      });
    }

    // Medium priority: Educational content
    recommendations.content.forEach((content: any, index: number) => {
      if (index < 2) {
        prioritized.push({
          type: 'content',
          priority: 'medium',
          title: content.title,
          item: content,
          cta: 'Read Article',
        });
      }
    });

    // Consultation recommendation if severity is high
    const shouldRecommendConsultation = true; // Based on analysis
    if (shouldRecommendConsultation) {
      prioritized.push({
        type: 'consultation',
        priority: 'high',
        title: 'Book a Free Discovery Call',
        item: {
          description: 'Get personalized guidance from our expert nutritionists',
          nutritionists: recommendations.nutritionists.slice(0, 2),
        },
        cta: 'Book Now',
      });
    }

    return prioritized;
  }

  private static async getUserHistory(userId: string) {
    const [journeys, quizResults, viewedContent] = await Promise.all([
      prisma.userJourney.findMany({
        where: { userId },
        include: { program: true },
      }),
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        take: 10,
      }),
      // Would fetch from analytics/audit logs
      [],
    ]);

    return {
      completedPrograms: journeys
        .filter((j) => j.status === 'COMPLETED')
        .map((j) => j.programId),
      successfulPrograms: journeys
        .filter((j) => j.status === 'COMPLETED' && j.progress?.satisfaction > 7)
        .map((j) => j.program.type),
      quizHistory: quizResults,
      viewedContent,
    };
  }

  private static matchProgramToConcern(programType: string, concern: string): boolean {
    const mapping: Record<string, string[]> = {
      GUT_HEALTH: ['digestive', 'bloating', 'ibs'],
      METABOLIC_RESET: ['energy', 'weight', 'metabolism'],
      PCOS_RESTORE: ['hormonal', 'pcos', 'fertility'],
      DIABETES_CARE: ['diabetes', 'blood_sugar', 'insulin'],
      DETOX_HORMONE: ['detox', 'hormonal', 'immune'],
    };

    return mapping[programType]?.includes(concern) || false;
  }

  private static generateProgramReason(program: any, analysis: any): string {
    const templates = [
      `Perfect for addressing your ${analysis.primaryConcern} concerns`,
      `${program._count?.journeys || 0} people with similar symptoms found success`,
      `Specifically designed for ${analysis.severity} ${analysis.primaryConcern} issues`,
    ];

    return templates[Math.floor(Math.random() * templates.length)];
  }

  private static extractInterestsFromAnalysis(analysis: any): string[] {
    const interests: string[] = [];

    // Map concerns to interests
    const concernToInterests: Record<string, string[]> = {
      digestive: ['gut-health', 'probiotics', 'digestion', 'ibs'],
      energy: ['metabolism', 'fatigue', 'nutrition', 'vitamins'],
      hormonal: ['hormones', 'pcos', 'thyroid', 'womens-health'],
      mental: ['stress', 'anxiety', 'mood', 'mindfulness'],
      immune: ['immunity', 'inflammation', 'detox', 'antioxidants'],
    };

    if (analysis.primaryConcern) {
      interests.push(...(concernToInterests[analysis.primaryConcern] || []));
    }

    analysis.secondaryConcerns.forEach((concern: string) => {
      interests.push(...(concernToInterests[concern] || []));
    });

    return [...new Set(interests)];
  }

  private static getRelevantSpecializations(analysis: any): string[] {
    const specs: string[] = [];

    if (analysis.primaryConcern === 'digestive') {
      specs.push('Gut Health', 'IBS Management');
    }
    if (analysis.primaryConcern === 'hormonal') {
      specs.push('Hormonal Balance', 'PCOS');
    }
    // ... more mappings

    return specs;
  }

  private static getRelevantResourceTypes(analysis: any): string[] {
    if (analysis.severity === 'high') {
      return ['tracker', 'guide', 'meal_plan'];
    }
    return ['guide', 'calculator', 'ebook'];
  }

  private static isTagRelevant(tag: string, analysis: any): boolean {
    const relevantTags = this.extractInterestsFromAnalysis(analysis);
    return relevantTags.some((interest) => 
      tag.toLowerCase().includes(interest.toLowerCase())
    );
  }

  private static async trackRecommendations(userId: string, recommendations: any[]) {
    // Store recommendations for analytics and ML training
    await prisma.recommendationLog.create({
      data: {
        userId,
        recommendations: recommendations,
        context: 'quiz_result',
        createdAt: new Date(),
      },
    });
  }
}
```

## Week 7: Content Management & PayloadCMS Integration

### Day 1-3: PayloadCMS Setup and Configuration

#### 1. PayloadCMS Configuration
```typescript
// apps/admin/src/payload.config.ts
import { buildConfig } from 'payload/config';
import path from 'path';
import { cloudStorage } from '@payloadcms/plugin-cloud-storage';
import { s3Adapter } from '@payloadcms/plugin-cloud-storage/s3';
import { seo } from '@payloadcms/plugin-seo';
import { formBuilder } from '@payloadcms/plugin-form-builder';

#### 1. Journey Controller
```typescript
// services/user/src/controllers/journey.controller.ts
import { Request, Response, NextFunction } from 'express';
import { JourneyService } from '../services/journey.service';
import { AppError } from '../utils/errors';

export class JourneyController {
  static async getCurrentJourney(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const journey = await JourneyService.getCurrentJourney(userId);

      res.json({
        success: true,
        data: journey,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getJourneyHistory(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;

      const journeys = await JourneyService.getJourneyHistory(userId);

      res.json({
        success: true,
        data: journeys,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createCheckIn(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const checkInData = req.body;

      const checkIn = await JourneyService.createCheckIn(userId, checkInData);

      res.json({
        success: true,
        message: 'Check-in recorded successfully',
        data: checkIn,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getCheckIns(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { journeyId } = req.params;
      const { startDate, endDate } = req.query;

      const checkIns = await JourneyService.getCheckIns(journeyId, userId, {
        startDate: startDate as string,
        endDate: endDate as string,
      });

      res.json({
        success: true,
        data: checkIns,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createMealEntry(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const mealData = req.body;

      const meal = await JourneyService.createMealEntry(userId, mealData);

      res.json({
        success: true,
        message: 'Meal entry recorded successfully',
        data: meal,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getMealEntries(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { date } = req.query;

      const meals = await JourneyService.getMealEntries(
        userId,
        date ? new Date(date as string) : new Date()
      );

      res.json({
        success: true,
        data: meals,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgressReport(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { journeyId } = req.params;

      const report = await JourneyService.generateProgressReport(journeyId, userId);

      res.json({
        success: true,
        data: report,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateMeasurements(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const measurements = req.body;

      const updated = await JourneyService.updateMeasurements(userId, measurements);

      res.json({
        success: true,
        message: 'Measurements updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Journey Service
```typescript
// services/user/src/services/journey.service.ts
import { prisma } from '@nutrition/database';
import { calculateCalories, analyzeMacros } from '../utils/nutrition.calculations';
import { generateChartData } from '../utils/chart.utils';

export class JourneyService {
  static async getCurrentJourney(userId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
      include: {
        program: true,
        checkIns: {
          orderBy: { date: 'desc' },
          take: 7,
        },
        mealEntries: {
          where: {
            date: {
              gte: new Date(new Date().setHours(0, 0, 0, 0)),
            },
          },
        },
      },
    });

    if (!journey) {
      return null;
    }

    // Calculate progress
    const totalDays = journey.program.duration;
    const elapsedDays = Math.floor(
      (new Date().getTime() - journey.startDate.getTime()) / (1000 * 60 * 60 * 24)
    );
    const progressPercentage = Math.min((elapsedDays / totalDays) * 100, 100);

    // Calculate today's nutrition
    const todayNutrition = this.calculateDailyNutrition(journey.mealEntries);

    return {
      ...journey,
      progress: {
        percentage: progressPercentage,
        elapsedDays,
        remainingDays: Math.max(totalDays - elapsedDays, 0),
      },
      todayNutrition,
    };
  }

  static async getJourneyHistory(userId: string) {
    return prisma.userJourney.findMany({
      where: { userId },
      include: {
        program: true,
        payments: {
          where: { status: 'SUCCESS' },
        },
      },
      orderBy: { startDate: 'desc' },
    });
  }

  static async createCheckIn(userId: string, data: any) {
    // Get active journey
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    // Create check-in
    const checkIn = await prisma.journeyCheckIn.create({
      data: {
        journeyId: journey.id,
        date: new Date(),
        ...data,
      },
    });

    // Update journey measurements if weight is provided
    if (data.weight) {
      await this.updateJourneyMeasurements(journey.id, { weight: data.weight });
    }

    return checkIn;
  }

  static async getCheckIns(journeyId: string, userId: string, filters: any) {
    // Verify journey belongs to user
    const journey = await prisma.userJourney.findFirst({
      where: {
        id: journeyId,
        userId,
      },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    const where: any = { journeyId };

    if (filters.startDate) {
      where.date = { gte: new Date(filters.startDate) };
    }

    if (filters.endDate) {
      where.date = { ...where.date, lte: new Date(filters.endDate) };
    }

    return prisma.journeyCheckIn.findMany({
      where,
      orderBy: { date: 'desc' },
    });
  }

  static async createMealEntry(userId: string, data: any) {
    // Get active journey
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    // Calculate nutrition info
    const nutritionInfo = await calculateCalories(data.foods);

    return prisma.mealEntry.create({
      data: {
        journeyId: journey.id,
        date: new Date(),
        mealType: data.mealType,
        foods: data.foods,
        ...nutritionInfo,
        notes: data.notes,
        photo: data.photo,
      },
    });
  }

  static async getMealEntries(userId: string, date: Date) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      return [];
    }

    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);

    return prisma.mealEntry.findMany({
      where: {
        journeyId: journey.id,
        date: {
          gte: startOfDay,
          lte: endOfDay,
        },
      },
      orderBy: { date: 'asc' },
    });
  }

  static async generateProgressReport(journeyId: string, userId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        id: journeyId,
        userId,
      },
      include: {
        program: true,
        checkIns: {
          orderBy: { date: 'asc' },
        },
        mealEntries: {
          orderBy: { date: 'asc' },
        },
      },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    // Generate various analytics
    const weightProgress = generateChartData(
      journey.checkIns.filter(c => c.weight),
      'date',
      'weight'
    );

    const energyTrend = generateChartData(
      journey.checkIns.filter(c => c.energy),
      'date',
      'energy'
    );

    const nutritionSummary = analyzeMacros(journey.mealEntries);

    // Calculate achievements
    const achievements = this.calculateAchievements(journey);

    return {
      journey: {
        id: journey.id,
        program: journey.program.name,
        startDate: journey.startDate,
        progress: journey.progress,
      },
      charts: {
        weightProgress,
        energyTrend,
      },
      nutritionSummary,
      achievements,
      recommendations: this.generateRecommendations(journey),
    };
  }

  static async updateMeasurements(userId: string, measurements: any) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        status: 'ACTIVE',
      },
    });

    if (!journey) {
      throw new Error('No active journey found');
    }

    return this.updateJourneyMeasurements(journey.id, measurements);
  }

  private static async updateJourneyMeasurements(journeyId: string, measurements: any) {
    const journey = await prisma.userJourney.findUnique({
      where: { id: journeyId },
    });

    if (!journey) {
      throw new Error('Journey not found');
    }

    const currentMeasurements = journey.measurements || {};
    const updatedMeasurements = {
      ...currentMeasurements,
      ...measurements,
      lastUpdated: new Date(),
    };

    return prisma.userJourney.update({
      where: { id: journeyId },
      data: { measurements: updatedMeasurements },
    });
  }

  private static calculateDailyNutrition(mealEntries: any[]) {
    return mealEntries.reduce(
      (total, meal) => ({
        calories: total.calories + (meal.calories || 0),
        protein: total.protein + (meal.protein || 0),
        carbs: total.carbs + (meal.carbs || 0),
        fat: total.fat + (meal.fat || 0),
        fiber: total.fiber + (meal.fiber || 0),
      }),
      { calories: 0, protein: 0, carbs: 0, fat: 0, fiber: 0 }
    );
  }

  private static calculateAchievements(journey: any) {
    const achievements = [];

    // Check-in streak
    const checkInDates = journey.checkIns.map((c: any) => 
      new Date(c.date).toDateString()
    );
    const uniqueDates = [...new Set(checkInDates)];
    
    if (uniqueDates.length >= 7) {
      achievements.push({
        type: 'streak',
        title: 'Week Warrior',
        description: 'Checked in for 7 days',
      });
    }

    // Weight loss
    if (journey.checkIns.length > 1) {
      const firstWeight = journey.checkIns[0].weight;
      const lastWeight = journey.checkIns[journey.checkIns.length - 1].weight;
      
      if (firstWeight && lastWeight && lastWeight < firstWeight) {
        const loss = firstWeight - lastWeight;
        achievements.push({
          type: 'weight_loss',
          title: 'Progress Made',
          description: `Lost ${loss.toFixed(1)} kg`,
        });
      }
    }

    return achievements;
  }

  private static generateRecommendations(journey: any) {
    const recommendations = [];

    // Analyze recent check-ins
    const recentCheckIns = journey.checkIns.slice(-7);
    const avgEnergy = recentCheckIns.reduce((sum: number, c: any) => 
      sum + (c.energy || 0), 0
    ) / recentCheckIns.length;

    if (avgEnergy < 5) {
      recommendations.push({
        type: 'energy',
        priority: 'high',
        message: 'Your energy levels seem low. Consider reviewing your sleep schedule and stress management.',
      });
    }

    // Analyze nutrition
    const recentMeals = journey.mealEntries.slice(-21); // Last week
    const avgProtein = recentMeals.reduce((sum: number, m: any) => 
      sum + (m.protein || 0), 0
    ) / recentMeals.length;

    if (avgProtein < 20) {
      recommendations.push({
        type: 'nutrition',
        priority: 'medium',
        message: 'Your protein intake appears low. Try to include more protein-rich foods in your meals.',
      });
    }

    return recommendations;
  }
}
```

## Week 4: Program & Consultation Management

### Day 1-2: Program Service

#### 1. Program Controller
```typescript
// services/consultation/src/controllers/program.controller.ts
import { Request, Response, NextFunction } from 'express';
import { ProgramService } from '../services/program.service';
import { AppError } from '../utils/errors';

export class ProgramController {
  static async getAllPrograms(req: Request, res: Response, next: NextFunction) {
    try {
      const { type, featured, page = 1, limit = 10 } = req.query;

      const programs = await ProgramService.getAllPrograms({
        type: type as string,
        featured: featured === 'true',
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: programs,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramBySlug(req: Request, res: Response, next: NextFunction) {
    try {
      const { slug } = req.params;
      const userId = req.user?.userId;

      const program = await ProgramService.getProgramBySlug(slug, userId);

      if (!program) {
        throw new AppError('Program not found', 404);
      }

      res.json({
        success: true,
        data: program,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramDetails(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const details = await ProgramService.getProgramDetails(id, userId);

      res.json({
        success: true,
        data: details,
      });
    } catch (error) {
      next(error);
    }
  }

  static async enrollInProgram(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { startDate } = req.body;

      const enrollment = await ProgramService.enrollInProgram(userId, id, startDate);

      res.json({
        success: true,
        message: 'Successfully enrolled in program',
        data: enrollment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getRecommendedPrograms(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.user?.userId;

      const recommendations = await ProgramService.getRecommendedPrograms(userId);

      res.json({
        success: true,
        data: recommendations,
      });
    } catch (error) {
      next(error);
    }
  }

  static async createReview(req: Request, res: Response, next: NextFunction) {
    try {
      const { userId } = req.user!;
      const { id } = req.params;
      const { rating, title, comment } = req.body;

      const review = await ProgramService.createReview(userId, id, {
        rating,
        title,
        comment,
      });

      res.json({
        success: true,
        message: 'Review submitted successfully',
        data: review,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProgramReviews(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { page = 1, limit = 10 } = req.query;

      const reviews = await ProgramService.getProgramReviews(id, {
        page: Number(page),
        limit: Number(limit),
      });

      res.json({
        success: true,
        data: reviews,
      });
    } catch (error) {
      next(error);
    }
  }
}
```

#### 2. Program Service
```typescript
// services/consultation/src/services/program.service.ts
import { prisma } from '@nutrition/database';
import { cacheManager } from '../utils/cache';
import { calculateProgramScore } from '../utils/recommendation.engine';

export class ProgramService {
  private static readonly CACHE_PREFIX = 'program:';
  private static readonly CACHE_TTL = 3600; // 1 hour

  static async getAllPrograms(options: {
    type?: string;
    featured?: boolean;
    page: number;
    limit: number;
  }) {
    const where: any = {
      isActive: true,
    };

    if (options.type) {
      where.type = options.type;
    }

    if (options.featured !== undefined) {
      where.isFeatured = options.featured;
    }

    const [programs, total] = await Promise.all([
      prisma.program.findMany({
        where,
        orderBy: [
          { isFeatured: 'desc' },
          { order: 'asc' },
          { createdAt: 'desc' },
        ],
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          _count: {
            select: {
              reviews: true,
              journeys: true,
            },
          },
        },
      }),
      prisma.program.count({ where }),
    ]);

    // Calculate average ratings
    const programsWithRatings = await Promise.all(
      programs.map(async (program) => {
        const avgRating = await prisma.programReview.aggregate({
          where: { programId: program.id },
          _avg: { rating: true },
        });

        return {
          ...program,
          averageRating: avgRating._avg.rating || 0,
        };
      })
    );

    return {
      programs: programsWithRatings,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
    };
  }

  static async getProgramBySlug(slug: string, userId?: string) {
    // Try cache first
    const cacheKey = `${this.CACHE_PREFIX}slug:${slug}`;
    const cached = await cacheManager.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const program = await prisma.program.findUnique({
      where: { slug, isActive: true },
      include: {
        reviews: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          include: {
            user: {
              select: {
                profile: {
                  select: {
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            },
          },
        },
        _count: {
          select: {
            reviews: true,
            journeys: true,
          },
        },
      },
    });

    if (!program) {
      return null;
    }

    // Calculate stats
    const [avgRating, completionRate] = await Promise.all([
      prisma.programReview.aggregate({
        where: { programId: program.id },
        _avg: { rating: true },
      }),
      this.calculateCompletionRate(program.id),
    ]);

    const enrichedProgram = {
      ...program,
      stats: {
        averageRating: avgRating._avg.rating || 0,
        totalReviews: program._count.reviews,
        totalEnrollments: program._count.journeys,
        completionRate,
      },
    };

    // Cache the result
    await cacheManager.set(cacheKey, JSON.stringify(enrichedProgram), this.CACHE_TTL);

    // Track view if user is logged in
    if (userId) {
      await this.trackProgramView(userId, program.id);
    }

    return enrichedProgram;
  }

  static async getProgramDetails(programId: string, userId?: string) {
    const program = await prisma.program.findUnique({
      where: { id: programId, isActive: true },
    });

    if (!program) {
      throw new Error('Program not found');
    }

    // Get detailed information
    const [
      weeklySchedule,
      sampleMealPlan,
      successStories,
      faqs,
      userProgress,
    ] = await Promise.all([
      this.getWeeklySchedule(programId),
      this.getSampleMealPlan(program.type),
      this.getSuccessStories(programId),
      this.getProgramFAQs(program.type),
      userId ? this.getUserProgramProgress(userId, programId) : null,
    ]);

    return {
      program,
      details: {
        weeklySchedule,
        sampleMealPlan,
        successStories,
        faqs,
      },
      userProgress,
    };
  }

  static async enrollInProgram(userId: string, programId: string, startDate?: Date) {
    // Check if already enrolled
    const existingJourney = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
        status: { in: ['ACTIVE', 'PAUSED'] },
      },
    });

    if (existingJourney) {
      throw new Error('Already enrolled in this program');
    }

    // Get program details
    const program = await prisma.program.findUnique({
      where: { id: programId },
    });

    if (!program) {
      throw new Error('Program not found');
    }

    // Create journey
    const journey = await prisma.userJourney.create({
      data: {
        userId,
        programId,
        startDate: startDate || new Date(),
        endDate: null, // Will be calculated based on progress
        status: 'ACTIVE',
        progress: {
          currentWeek: 1,
          completedModules: [],
          milestones: [],
        },
      },
    });

    // Create initial meal plan
    await this.createInitialMealPlan(journey.id, program.type);

    // Schedule welcome email
    await this.scheduleWelcomeSequence(userId, programId);

    return journey;
  }

  static async getRecommendedPrograms(userId?: string) {
    if (!userId) {
      // Return popular programs for non-authenticated users
      return this.getPopularPrograms();
    }

    // Get user data for recommendation
    const [userData, quizResults, previousPrograms] = await Promise.all([
      prisma.user.findUnique({
        where: { id: userId },
        include: {
          profile: true,
          journeys: {
            include: { program: true },
          },
        },
      }),
      prisma.quizResult.findMany({
        where: { userId },
        orderBy: { completedAt: 'desc' },
        take: 5,
      }),
      prisma.userJourney.findMany({
        where: { userId },
        include: { program: true },
      }),
    ]);

    if (!userData) {
      return this.getPopularPrograms();
    }

    // Get all active programs
    const programs = await prisma.program.findMany({
      where: { isActive: true },
      include: {
        _count: {
          select: {
            reviews: true,
            journeys: true,
          },
        },
      },
    });

    // Score each program based on user data
    const scoredPrograms = programs.map((program) => ({
      ...program,
      score: calculateProgramScore(program, {
        userData,
        quizResults,
        previousPrograms,
      }),
    }));

    // Sort by score and return top 5
    return scoredPrograms
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map(({ score, ...program }) => program);
  }

  static async createReview(userId: string, programId: string, data: {
    rating: number;
    title?: string;
    comment?: string;
  }) {
    // Check if user has completed the program
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
        status: 'COMPLETED',
      },
    });

    if (!journey) {
      throw new Error('You must complete the program before reviewing');
    }

    // Check if already reviewed
    const existingReview = await prisma.programReview.findUnique({
      where: {
        programId_userId: {
          programId,
          userId,
        },
      },
    });

    if (existingReview) {
      throw new Error('You have already reviewed this program');
    }

    // Create review
    const review = await prisma.programReview.create({
      data: {
        programId,
        userId,
        rating: data.rating,
        title: data.title,
        comment: data.comment,
        isVerified: true, // Since they completed the program
      },
    });

    // Update program rating cache
    await this.updateProgramRatingCache(programId);

    return review;
  }

  static async getProgramReviews(programId: string, options: {
    page: number;
    limit: number;
  }) {
    const [reviews, total] = await Promise.all([
      prisma.programReview.findMany({
        where: { programId },
        orderBy: [
          { isVerified: 'desc' },
          { createdAt: 'desc' },
        ],
        skip: (options.page - 1) * options.limit,
        take: options.limit,
        include: {
          user: {
            select: {
              profile: {
                select: {
                  firstName: true,
                  lastName: true,
                  avatar: true,
                },
              },
            },
          },
        },
      }),
      prisma.programReview.count({ where: { programId } }),
    ]);

    // Get rating distribution
    const ratingDistribution = await prisma.programReview.groupBy({
      by: ['rating'],
      where: { programId },
      _count: true,
    });

    return {
      reviews,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        pages: Math.ceil(total / options.limit),
      },
      stats: {
        distribution: ratingDistribution.reduce((acc, item) => {
          acc[item.rating] = item._count;
          return acc;
        }, {} as Record<number, number>),
      },
    };
  }

  private static async calculateCompletionRate(programId: string) {
    const journeys = await prisma.userJourney.findMany({
      where: { programId },
      select: { status: true },
    });

    if (journeys.length === 0) return 0;

    const completed = journeys.filter(j => j.status === 'COMPLETED').length;
    return Math.round((completed / journeys.length) * 100);
  }

  private static async getPopularPrograms() {
    return prisma.program.findMany({
      where: { isActive: true, isFeatured: true },
      orderBy: { order: 'asc' },
      take: 5,
    });
  }

  private static async trackProgramView(userId: string, programId: string) {
    // Implement view tracking for analytics
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'VIEW_PROGRAM',
        entity: 'program',
        entityId: programId,
      },
    });
  }

  private static async getWeeklySchedule(programId: string) {
    // This would be stored in program metadata or a separate table
    // For now, returning a sample structure
    return {
      week1: {
        title: 'Foundation Week',
        activities: [
          'Initial health assessment',
          'Personalized meal plan creation',
          'Introduction to food journaling',
        ],
      },
      week2: {
        title: 'Implementation Week',
        activities: [
          'Start meal plan',
          'Daily check-ins',
          'First consultation call',
        ],
      },
      // ... more weeks
    };
  }

  private static async getSampleMealPlan(programType: string) {
    // Fetch from a meal plan service or database
    // This is a simplified example
    const mealPlans: Record<string, any> = {
      GUT_HEALTH: {
        day1: {
          breakfast: 'Overnight oats with chia seeds and berries',
          lunch: 'Grilled chicken salad with fermented vegetables',
          dinner: 'Baked salmon with steamed broccoli and quinoa',
          snacks: ['Apple slices with almond butter', 'Kefir smoothie'],
        },
        // ... more days
      },
      // ... other program types
    };

    return mealPlans[programType] || {};
  }

  private static async getSuccessStories(programId: string) {
    return prisma.programReview.findMany({
      where: {
        programId,
        rating: { gte: 4 },
        comment: { not: null },
        isVerified: true,
      },
      select: {
        rating: true,
        title: true,
        comment: true,
        createdAt: true,
        user: {
          select: {
            profile: {
              select: {
                firstName: true,
              },
            },
          },
        },
      },
      take: 3,
      orderBy: { rating: 'desc' },
    });
  }

  private static async getProgramFAQs(programType: string) {
    // This would be fetched from a CMS or database
    // Simplified example
    const faqs: Record<string, any[]> = {
      GUT_HEALTH: [
        {
          question: 'How long before I see results?',
          answer: 'Most clients report improvements in bloating and digestion within 2-3 weeks.',
        },
        {
          question: 'Can I follow this program if I have food allergies?',
          answer: 'Yes, all meal plans are customized based on your dietary restrictions.',
        },
      ],
      // ... other types
    };

    return faqs[programType] || [];
  }

  private static async getUserProgramProgress(userId: string, programId: string) {
    const journey = await prisma.userJourney.findFirst({
      where: {
        userId,
        programId,
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!journey) {
      return null;
    }

    return {
      status: journey.status,
      startDate: journey.startDate,
      progress: journey.progress,
      completedAt: journey.completedAt,
    };
  }

  private static async createInitialMealPlan(journeyId: string, programType: string) {
    // This would integrate with a meal planning service
    // For now, we'll store a reference in the journey
    await prisma.userJourney.update({
      where: { id: journeyId },
      data: {
        mealPlans: {
          week1: 'Generated based on program type',
          status: 'pending_nutritionist_review',
        },
      },
    });
  }

  private static async scheduleWelcomeSequence(userId: string, programId: string) {
    // Schedule a series of welcome emails
    const emailSequence = [
      { delay: 0, template: 'program_welcome' },
      { delay: 1, template: 'program_day1_tips' },
      { delay: 3, template: 'program_check_in' },
      { delay: 7, template: 'program_week1_summary' },
    ];

    for (const email of emailSequence) {
      await prisma.notification.create({
        data: {
          userId,
          type: 'email',
          category: 'journey',
          title: `Program Email - ${email.template}`,
          content: JSON.stringify({ programId, template: email.template }),
          status: 'PENDING',
          createdAt: new Date(Date.now() + email.delay * 24 * 60 * 60 * 1000),
        },
      });
    }
  }

  private static async updateProgramRatingCache(programId: string) {
    const avgRating = await prisma.programReview.aggregate({
      where: { programId },
      _avg: { rating: true },
      _count: true,
    });

    // Update cache
    const cacheKey = `${this.CACHE_PREFIX}rating:${programId}`;
    await cacheManager.set(
      cacheKey,
      JSON.stringify({
        average: avgRating._avg.rating || 0,
        count: avgRating._count,
      }),
      86400 // 24 hours
    );
  }
}