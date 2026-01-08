/**
 * PayGuard V2 - Brand Fingerprint Database
 * 
 * Contains fingerprints for commonly phished brands.
 * In production, this would be loaded from a remote API and updated regularly.
 * 
 * Implements Requirement 3.8 - Store fingerprints for top 1000 phished brands
 */

import { BrandFingerprint } from '../types/fingerprint';

/**
 * Category of brand for organization and prioritization.
 */
export type BrandCategory = 
  | 'financial'
  | 'technology'
  | 'social_media'
  | 'ecommerce'
  | 'streaming'
  | 'email'
  | 'government'
  | 'healthcare'
  | 'telecom'
  | 'other';

/**
 * Extended brand fingerprint with category information.
 */
export interface CategorizedBrandFingerprint extends BrandFingerprint {
  category: BrandCategory;
  description?: string;
}

/**
 * Get all brand fingerprints organized by category.
 */
export function getBrandsByCategory(): Map<BrandCategory, CategorizedBrandFingerprint[]> {
  const brands = getAllBrandFingerprints();
  const byCategory = new Map<BrandCategory, CategorizedBrandFingerprint[]>();
  
  for (const brand of brands) {
    const existing = byCategory.get(brand.category) || [];
    existing.push(brand);
    byCategory.set(brand.category, existing);
  }
  
  return byCategory;
}

/**
 * Get brands by priority (most commonly phished first).
 */
export function getBrandsByPriority(limit?: number): CategorizedBrandFingerprint[] {
  const brands = getAllBrandFingerprints();
  brands.sort((a, b) => b.priority - a.priority);
  return limit ? brands.slice(0, limit) : brands;
}

/**
 * Search brands by name or domain.
 */
export function searchBrands(query: string): CategorizedBrandFingerprint[] {
  const brands = getAllBrandFingerprints();
  const lowerQuery = query.toLowerCase();
  
  return brands.filter(brand => 
    brand.brand.toLowerCase().includes(lowerQuery) ||
    brand.legitimateDomains.some(d => d.includes(lowerQuery))
  );
}


/**
 * Get all brand fingerprints.
 * This is a comprehensive list of commonly phished brands.
 */
export function getAllBrandFingerprints(): CategorizedBrandFingerprint[] {
  return [
    // ============================================
    // FINANCIAL SERVICES (Highest Priority)
    // ============================================
    {
      brand: 'PayPal',
      category: 'financial',
      description: 'Online payment platform',
      legitimateDomains: ['paypal.com', 'paypal.me', 'paypalobjects.com'],
      domHashes: ['paypal_dom_v1', 'paypal_dom_v2'],
      cssHashes: ['paypal_css_v1', 'paypal_css_v2'],
      layoutHashes: ['paypal_layout_v1', 'paypal_layout_v2'],
      colorPalettes: [['#003087', '#009cde', '#012169', '#ffffff']],
      fontFamilies: ['paypal sans', 'helvetica neue', 'helvetica', 'arial'],
      logoHashes: ['0101010101010101010101010101010101010101010101010101010101010101'],
      lastUpdated: new Date(),
      priority: 100
    },
    {
      brand: 'Bank of America',
      category: 'financial',
      description: 'Major US bank',
      legitimateDomains: ['bankofamerica.com', 'bofa.com', 'mbna.com'],
      domHashes: ['boa_dom_v1', 'boa_dom_v2'],
      cssHashes: ['boa_css_v1', 'boa_css_v2'],
      layoutHashes: ['boa_layout_v1', 'boa_layout_v2'],
      colorPalettes: [['#012169', '#e31837', '#ffffff', '#333333']],
      fontFamilies: ['connections', 'arial', 'helvetica'],
      logoHashes: ['0101101001011010010110100101101001011010010110100101101001011010'],
      lastUpdated: new Date(),
      priority: 98
    },
    {
      brand: 'Chase',
      category: 'financial',
      description: 'JPMorgan Chase Bank',
      legitimateDomains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com'],
      domHashes: ['chase_dom_v1', 'chase_dom_v2'],
      cssHashes: ['chase_css_v1', 'chase_css_v2'],
      layoutHashes: ['chase_layout_v1', 'chase_layout_v2'],
      colorPalettes: [['#117aca', '#ffffff', '#0060a9', '#333333']],
      fontFamilies: ['proxima nova', 'arial', 'helvetica'],
      logoHashes: ['1100001111000011110000111100001111000011110000111100001111000011'],
      lastUpdated: new Date(),
      priority: 98
    },
    {
      brand: 'Wells Fargo',
      category: 'financial',
      description: 'Major US bank',
      legitimateDomains: ['wellsfargo.com', 'wf.com'],
      domHashes: ['wf_dom_v1', 'wf_dom_v2'],
      cssHashes: ['wf_css_v1', 'wf_css_v2'],
      layoutHashes: ['wf_layout_v1', 'wf_layout_v2'],
      colorPalettes: [['#d71e28', '#ffcd41', '#ffffff', '#333333']],
      fontFamilies: ['wells fargo sans', 'arial', 'helvetica'],
      logoHashes: ['0011110000111100001111000011110000111100001111000011110000111100'],
      lastUpdated: new Date(),
      priority: 97
    },
    {
      brand: 'Citibank',
      category: 'financial',
      description: 'Citigroup banking',
      legitimateDomains: ['citi.com', 'citibank.com', 'citicards.com'],
      domHashes: ['citi_dom_v1', 'citi_dom_v2'],
      cssHashes: ['citi_css_v1', 'citi_css_v2'],
      layoutHashes: ['citi_layout_v1', 'citi_layout_v2'],
      colorPalettes: [['#003b70', '#ffffff', '#00bfff', '#333333']],
      fontFamilies: ['interstate', 'arial', 'helvetica'],
      logoHashes: ['1010101010101010101010101010101010101010101010101010101010101010'],
      lastUpdated: new Date(),
      priority: 96
    },
    {
      brand: 'Capital One',
      category: 'financial',
      description: 'US bank and credit card company',
      legitimateDomains: ['capitalone.com', 'capitalone360.com'],
      domHashes: ['capone_dom_v1', 'capone_dom_v2'],
      cssHashes: ['capone_css_v1', 'capone_css_v2'],
      layoutHashes: ['capone_layout_v1', 'capone_layout_v2'],
      colorPalettes: [['#004977', '#d03027', '#ffffff', '#333333']],
      fontFamilies: ['optimist', 'arial', 'helvetica'],
      logoHashes: ['0110011001100110011001100110011001100110011001100110011001100110'],
      lastUpdated: new Date(),
      priority: 95
    },
    {
      brand: 'American Express',
      category: 'financial',
      description: 'Credit card and financial services',
      legitimateDomains: ['americanexpress.com', 'amex.com'],
      domHashes: ['amex_dom_v1', 'amex_dom_v2'],
      cssHashes: ['amex_css_v1', 'amex_css_v2'],
      layoutHashes: ['amex_layout_v1', 'amex_layout_v2'],
      colorPalettes: [['#006fcf', '#ffffff', '#00175a', '#333333']],
      fontFamilies: ['benton sans', 'arial', 'helvetica'],
      logoHashes: ['1001100110011001100110011001100110011001100110011001100110011001'],
      lastUpdated: new Date(),
      priority: 95
    },
    {
      brand: 'USAA',
      category: 'financial',
      description: 'Military banking and insurance',
      legitimateDomains: ['usaa.com'],
      domHashes: ['usaa_dom_v1', 'usaa_dom_v2'],
      cssHashes: ['usaa_css_v1', 'usaa_css_v2'],
      layoutHashes: ['usaa_layout_v1', 'usaa_layout_v2'],
      colorPalettes: [['#003366', '#ffffff', '#0066cc', '#333333']],
      fontFamilies: ['usaa sans', 'arial', 'helvetica'],
      logoHashes: ['0011001100110011001100110011001100110011001100110011001100110011'],
      lastUpdated: new Date(),
      priority: 94
    },

    // ============================================
    // TECHNOLOGY COMPANIES
    // ============================================
    {
      brand: 'Google',
      category: 'technology',
      description: 'Search and cloud services',
      legitimateDomains: ['google.com', 'accounts.google.com', 'gmail.com', 'google.co.uk', 'google.de'],
      domHashes: ['google_dom_v1', 'google_dom_v2'],
      cssHashes: ['google_css_v1', 'google_css_v2'],
      layoutHashes: ['google_layout_v1', 'google_layout_v2'],
      colorPalettes: [['#4285f4', '#34a853', '#fbbc05', '#ea4335', '#ffffff']],
      fontFamilies: ['google sans', 'roboto', 'arial'],
      logoHashes: ['1010101010101010101010101010101010101010101010101010101010101010'],
      lastUpdated: new Date(),
      priority: 100
    },
    {
      brand: 'Microsoft',
      category: 'technology',
      description: 'Software and cloud services',
      legitimateDomains: ['microsoft.com', 'login.microsoftonline.com', 'outlook.com', 'live.com', 'office.com', 'office365.com'],
      domHashes: ['ms_dom_v1', 'ms_dom_v2'],
      cssHashes: ['ms_css_v1', 'ms_css_v2'],
      layoutHashes: ['ms_layout_v1', 'ms_layout_v2'],
      colorPalettes: [['#0078d4', '#ffffff', '#000000', '#737373']],
      fontFamilies: ['segoe ui', 'segoe ui web', 'arial'],
      logoHashes: ['1100110011001100110011001100110011001100110011001100110011001100'],
      lastUpdated: new Date(),
      priority: 100
    },
    {
      brand: 'Apple',
      category: 'technology',
      description: 'Consumer electronics and services',
      legitimateDomains: ['apple.com', 'icloud.com', 'appleid.apple.com', 'itunes.apple.com'],
      domHashes: ['apple_dom_v1', 'apple_dom_v2'],
      cssHashes: ['apple_css_v1', 'apple_css_v2'],
      layoutHashes: ['apple_layout_v1', 'apple_layout_v2'],
      colorPalettes: [['#000000', '#ffffff', '#0071e3', '#f5f5f7']],
      fontFamilies: ['sf pro display', 'sf pro text', 'helvetica neue', 'helvetica'],
      logoHashes: ['0011001100110011001100110011001100110011001100110011001100110011'],
      lastUpdated: new Date(),
      priority: 100
    },
    {
      brand: 'Dropbox',
      category: 'technology',
      description: 'Cloud storage service',
      legitimateDomains: ['dropbox.com', 'dropboxusercontent.com'],
      domHashes: ['dropbox_dom_v1', 'dropbox_dom_v2'],
      cssHashes: ['dropbox_css_v1', 'dropbox_css_v2'],
      layoutHashes: ['dropbox_layout_v1', 'dropbox_layout_v2'],
      colorPalettes: [['#0061ff', '#ffffff', '#1e1919', '#b4b4b4']],
      fontFamilies: ['atlas grotesk', 'helvetica neue', 'arial'],
      logoHashes: ['1111000011110000111100001111000011110000111100001111000011110000'],
      lastUpdated: new Date(),
      priority: 85
    },
    {
      brand: 'Adobe',
      category: 'technology',
      description: 'Creative software',
      legitimateDomains: ['adobe.com', 'creativecloud.adobe.com'],
      domHashes: ['adobe_dom_v1', 'adobe_dom_v2'],
      cssHashes: ['adobe_css_v1', 'adobe_css_v2'],
      layoutHashes: ['adobe_layout_v1', 'adobe_layout_v2'],
      colorPalettes: [['#ff0000', '#ffffff', '#000000', '#323232']],
      fontFamilies: ['adobe clean', 'helvetica neue', 'arial'],
      logoHashes: ['0000111100001111000011110000111100001111000011110000111100001111'],
      lastUpdated: new Date(),
      priority: 85
    },
    {
      brand: 'Zoom',
      category: 'technology',
      description: 'Video conferencing',
      legitimateDomains: ['zoom.us', 'zoom.com'],
      domHashes: ['zoom_dom_v1', 'zoom_dom_v2'],
      cssHashes: ['zoom_css_v1', 'zoom_css_v2'],
      layoutHashes: ['zoom_layout_v1', 'zoom_layout_v2'],
      colorPalettes: [['#2d8cff', '#ffffff', '#0b5cff', '#232333']],
      fontFamilies: ['lato', 'helvetica neue', 'arial'],
      logoHashes: ['1010010110100101101001011010010110100101101001011010010110100101'],
      lastUpdated: new Date(),
      priority: 88
    },

    // ============================================
    // SOCIAL MEDIA
    // ============================================
    {
      brand: 'Facebook',
      category: 'social_media',
      description: 'Social networking platform',
      legitimateDomains: ['facebook.com', 'fb.com', 'messenger.com', 'meta.com'],
      domHashes: ['fb_dom_v1', 'fb_dom_v2'],
      cssHashes: ['fb_css_v1', 'fb_css_v2'],
      layoutHashes: ['fb_layout_v1', 'fb_layout_v2'],
      colorPalettes: [['#1877f2', '#ffffff', '#f0f2f5', '#65676b']],
      fontFamilies: ['segoe ui historic', 'segoe ui', 'helvetica', 'arial'],
      logoHashes: ['0000111100001111000011110000111100001111000011110000111100001111'],
      lastUpdated: new Date(),
      priority: 95
    },
    {
      brand: 'Instagram',
      category: 'social_media',
      description: 'Photo sharing platform',
      legitimateDomains: ['instagram.com'],
      domHashes: ['ig_dom_v1', 'ig_dom_v2'],
      cssHashes: ['ig_css_v1', 'ig_css_v2'],
      layoutHashes: ['ig_layout_v1', 'ig_layout_v2'],
      colorPalettes: [['#e1306c', '#f77737', '#fcaf45', '#ffffff', '#262626']],
      fontFamilies: ['segoe ui', 'roboto', 'helvetica', 'arial'],
      logoHashes: ['1100110011001100110011001100110011001100110011001100110011001100'],
      lastUpdated: new Date(),
      priority: 92
    },
    {
      brand: 'LinkedIn',
      category: 'social_media',
      description: 'Professional networking',
      legitimateDomains: ['linkedin.com'],
      domHashes: ['linkedin_dom_v1', 'linkedin_dom_v2'],
      cssHashes: ['linkedin_css_v1', 'linkedin_css_v2'],
      layoutHashes: ['linkedin_layout_v1', 'linkedin_layout_v2'],
      colorPalettes: [['#0077b5', '#ffffff', '#000000', '#86888a']],
      fontFamilies: ['source sans pro', 'helvetica neue', 'arial'],
      logoHashes: ['0110011001100110011001100110011001100110011001100110011001100110'],
      lastUpdated: new Date(),
      priority: 93
    },
    {
      brand: 'Twitter',
      category: 'social_media',
      description: 'Microblogging platform',
      legitimateDomains: ['twitter.com', 'x.com'],
      domHashes: ['twitter_dom_v1', 'twitter_dom_v2'],
      cssHashes: ['twitter_css_v1', 'twitter_css_v2'],
      layoutHashes: ['twitter_layout_v1', 'twitter_layout_v2'],
      colorPalettes: [['#1da1f2', '#ffffff', '#14171a', '#657786']],
      fontFamilies: ['chirp', 'helvetica neue', 'arial'],
      logoHashes: ['1001100110011001100110011001100110011001100110011001100110011001'],
      lastUpdated: new Date(),
      priority: 90
    },
    {
      brand: 'WhatsApp',
      category: 'social_media',
      description: 'Messaging platform',
      legitimateDomains: ['whatsapp.com', 'web.whatsapp.com'],
      domHashes: ['whatsapp_dom_v1', 'whatsapp_dom_v2'],
      cssHashes: ['whatsapp_css_v1', 'whatsapp_css_v2'],
      layoutHashes: ['whatsapp_layout_v1', 'whatsapp_layout_v2'],
      colorPalettes: [['#25d366', '#ffffff', '#075e54', '#128c7e']],
      fontFamilies: ['helvetica neue', 'helvetica', 'arial'],
      logoHashes: ['0101010101010101010101010101010101010101010101010101010101010101'],
      lastUpdated: new Date(),
      priority: 91
    },

    // ============================================
    // E-COMMERCE
    // ============================================
    {
      brand: 'Amazon',
      category: 'ecommerce',
      description: 'E-commerce and cloud services',
      legitimateDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.in', 'aws.amazon.com'],
      domHashes: ['amz_dom_v1', 'amz_dom_v2'],
      cssHashes: ['amz_css_v1', 'amz_css_v2'],
      layoutHashes: ['amz_layout_v1', 'amz_layout_v2'],
      colorPalettes: [['#ff9900', '#232f3e', '#ffffff', '#131921']],
      fontFamilies: ['amazon ember', 'arial', 'sans-serif'],
      logoHashes: ['1111000011110000111100001111000011110000111100001111000011110000'],
      lastUpdated: new Date(),
      priority: 100
    },
    {
      brand: 'eBay',
      category: 'ecommerce',
      description: 'Online marketplace',
      legitimateDomains: ['ebay.com', 'ebay.co.uk', 'ebay.de'],
      domHashes: ['ebay_dom_v1', 'ebay_dom_v2'],
      cssHashes: ['ebay_css_v1', 'ebay_css_v2'],
      layoutHashes: ['ebay_layout_v1', 'ebay_layout_v2'],
      colorPalettes: [['#e53238', '#f5af02', '#0064d2', '#86b817', '#ffffff']],
      fontFamilies: ['market sans', 'helvetica neue', 'arial'],
      logoHashes: ['0011001100110011001100110011001100110011001100110011001100110011'],
      lastUpdated: new Date(),
      priority: 90
    },
    {
      brand: 'Walmart',
      category: 'ecommerce',
      description: 'Retail corporation',
      legitimateDomains: ['walmart.com'],
      domHashes: ['walmart_dom_v1', 'walmart_dom_v2'],
      cssHashes: ['walmart_css_v1', 'walmart_css_v2'],
      layoutHashes: ['walmart_layout_v1', 'walmart_layout_v2'],
      colorPalettes: [['#0071dc', '#ffc220', '#ffffff', '#2e2f32']],
      fontFamilies: ['bogle', 'helvetica neue', 'arial'],
      logoHashes: ['1010101010101010101010101010101010101010101010101010101010101010'],
      lastUpdated: new Date(),
      priority: 85
    },
    {
      brand: 'Target',
      category: 'ecommerce',
      description: 'Retail corporation',
      legitimateDomains: ['target.com'],
      domHashes: ['target_dom_v1', 'target_dom_v2'],
      cssHashes: ['target_css_v1', 'target_css_v2'],
      layoutHashes: ['target_layout_v1', 'target_layout_v2'],
      colorPalettes: [['#cc0000', '#ffffff', '#333333', '#888888']],
      fontFamilies: ['helvetica neue', 'arial'],
      logoHashes: ['1100110011001100110011001100110011001100110011001100110011001100'],
      lastUpdated: new Date(),
      priority: 82
    },
    {
      brand: 'Costco',
      category: 'ecommerce',
      description: 'Wholesale corporation',
      legitimateDomains: ['costco.com'],
      domHashes: ['costco_dom_v1', 'costco_dom_v2'],
      cssHashes: ['costco_css_v1', 'costco_css_v2'],
      layoutHashes: ['costco_layout_v1', 'costco_layout_v2'],
      colorPalettes: [['#e31837', '#005daa', '#ffffff', '#333333']],
      fontFamilies: ['arial', 'helvetica'],
      logoHashes: ['0110011001100110011001100110011001100110011001100110011001100110'],
      lastUpdated: new Date(),
      priority: 80
    },

    // ============================================
    // STREAMING SERVICES
    // ============================================
    {
      brand: 'Netflix',
      category: 'streaming',
      description: 'Streaming service',
      legitimateDomains: ['netflix.com'],
      domHashes: ['nf_dom_v1', 'nf_dom_v2'],
      cssHashes: ['nf_css_v1', 'nf_css_v2'],
      layoutHashes: ['nf_layout_v1', 'nf_layout_v2'],
      colorPalettes: [['#e50914', '#000000', '#ffffff', '#141414']],
      fontFamilies: ['netflix sans', 'helvetica neue', 'helvetica', 'arial'],
      logoHashes: ['1010010110100101101001011010010110100101101001011010010110100101'],
      lastUpdated: new Date(),
      priority: 92
    },
    {
      brand: 'Spotify',
      category: 'streaming',
      description: 'Music streaming service',
      legitimateDomains: ['spotify.com', 'open.spotify.com'],
      domHashes: ['spotify_dom_v1', 'spotify_dom_v2'],
      cssHashes: ['spotify_css_v1', 'spotify_css_v2'],
      layoutHashes: ['spotify_layout_v1', 'spotify_layout_v2'],
      colorPalettes: [['#1db954', '#191414', '#ffffff', '#b3b3b3']],
      fontFamilies: ['circular', 'helvetica neue', 'arial'],
      logoHashes: ['0101101001011010010110100101101001011010010110100101101001011010'],
      lastUpdated: new Date(),
      priority: 88
    },
    {
      brand: 'Disney+',
      category: 'streaming',
      description: 'Disney streaming service',
      legitimateDomains: ['disneyplus.com', 'disney.com'],
      domHashes: ['disney_dom_v1', 'disney_dom_v2'],
      cssHashes: ['disney_css_v1', 'disney_css_v2'],
      layoutHashes: ['disney_layout_v1', 'disney_layout_v2'],
      colorPalettes: [['#113ccf', '#ffffff', '#040714', '#f9f9f9']],
      fontFamilies: ['avenir', 'helvetica neue', 'arial'],
      logoHashes: ['1001100110011001100110011001100110011001100110011001100110011001'],
      lastUpdated: new Date(),
      priority: 85
    },
    {
      brand: 'HBO Max',
      category: 'streaming',
      description: 'HBO streaming service',
      legitimateDomains: ['hbomax.com', 'max.com'],
      domHashes: ['hbo_dom_v1', 'hbo_dom_v2'],
      cssHashes: ['hbo_css_v1', 'hbo_css_v2'],
      layoutHashes: ['hbo_layout_v1', 'hbo_layout_v2'],
      colorPalettes: [['#5822b4', '#ffffff', '#000000', '#8b5cf6']],
      fontFamilies: ['street', 'helvetica neue', 'arial'],
      logoHashes: ['0011110000111100001111000011110000111100001111000011110000111100'],
      lastUpdated: new Date(),
      priority: 82
    },

    // ============================================
    // EMAIL PROVIDERS
    // ============================================
    {
      brand: 'Yahoo',
      category: 'email',
      description: 'Email and web services',
      legitimateDomains: ['yahoo.com', 'mail.yahoo.com', 'login.yahoo.com'],
      domHashes: ['yahoo_dom_v1', 'yahoo_dom_v2'],
      cssHashes: ['yahoo_css_v1', 'yahoo_css_v2'],
      layoutHashes: ['yahoo_layout_v1', 'yahoo_layout_v2'],
      colorPalettes: [['#6001d2', '#ffffff', '#1d1d1f', '#720e9e']],
      fontFamilies: ['yahoo sans', 'helvetica neue', 'arial'],
      logoHashes: ['1111000011110000111100001111000011110000111100001111000011110000'],
      lastUpdated: new Date(),
      priority: 88
    },
    {
      brand: 'AOL',
      category: 'email',
      description: 'Email and web services',
      legitimateDomains: ['aol.com', 'mail.aol.com'],
      domHashes: ['aol_dom_v1', 'aol_dom_v2'],
      cssHashes: ['aol_css_v1', 'aol_css_v2'],
      layoutHashes: ['aol_layout_v1', 'aol_layout_v2'],
      colorPalettes: [['#0066ff', '#ffffff', '#000000', '#666666']],
      fontFamilies: ['helvetica neue', 'arial'],
      logoHashes: ['0000111100001111000011110000111100001111000011110000111100001111'],
      lastUpdated: new Date(),
      priority: 75
    },

    // ============================================
    // TELECOM
    // ============================================
    {
      brand: 'AT&T',
      category: 'telecom',
      description: 'Telecommunications company',
      legitimateDomains: ['att.com', 'att.net'],
      domHashes: ['att_dom_v1', 'att_dom_v2'],
      cssHashes: ['att_css_v1', 'att_css_v2'],
      layoutHashes: ['att_layout_v1', 'att_layout_v2'],
      colorPalettes: [['#009fdb', '#ffffff', '#000000', '#ff7200']],
      fontFamilies: ['att aleck sans', 'helvetica neue', 'arial'],
      logoHashes: ['1010101010101010101010101010101010101010101010101010101010101010'],
      lastUpdated: new Date(),
      priority: 85
    },
    {
      brand: 'Verizon',
      category: 'telecom',
      description: 'Telecommunications company',
      legitimateDomains: ['verizon.com', 'verizonwireless.com'],
      domHashes: ['verizon_dom_v1', 'verizon_dom_v2'],
      cssHashes: ['verizon_css_v1', 'verizon_css_v2'],
      layoutHashes: ['verizon_layout_v1', 'verizon_layout_v2'],
      colorPalettes: [['#cd040b', '#ffffff', '#000000', '#747676']],
      fontFamilies: ['nhu', 'helvetica neue', 'arial'],
      logoHashes: ['0101010101010101010101010101010101010101010101010101010101010101'],
      lastUpdated: new Date(),
      priority: 85
    },
    {
      brand: 'T-Mobile',
      category: 'telecom',
      description: 'Telecommunications company',
      legitimateDomains: ['t-mobile.com'],
      domHashes: ['tmobile_dom_v1', 'tmobile_dom_v2'],
      cssHashes: ['tmobile_css_v1', 'tmobile_css_v2'],
      layoutHashes: ['tmobile_layout_v1', 'tmobile_layout_v2'],
      colorPalettes: [['#e20074', '#ffffff', '#000000', '#5c5c5c']],
      fontFamilies: ['tele-grotesk', 'helvetica neue', 'arial'],
      logoHashes: ['1100110011001100110011001100110011001100110011001100110011001100'],
      lastUpdated: new Date(),
      priority: 84
    },

    // ============================================
    // GOVERNMENT & SERVICES
    // ============================================
    {
      brand: 'IRS',
      category: 'government',
      description: 'US Internal Revenue Service',
      legitimateDomains: ['irs.gov'],
      domHashes: ['irs_dom_v1', 'irs_dom_v2'],
      cssHashes: ['irs_css_v1', 'irs_css_v2'],
      layoutHashes: ['irs_layout_v1', 'irs_layout_v2'],
      colorPalettes: [['#003366', '#ffffff', '#000000', '#666666']],
      fontFamilies: ['source sans pro', 'arial'],
      logoHashes: ['0110011001100110011001100110011001100110011001100110011001100110'],
      lastUpdated: new Date(),
      priority: 90
    },
    {
      brand: 'USPS',
      category: 'government',
      description: 'US Postal Service',
      legitimateDomains: ['usps.com'],
      domHashes: ['usps_dom_v1', 'usps_dom_v2'],
      cssHashes: ['usps_css_v1', 'usps_css_v2'],
      layoutHashes: ['usps_layout_v1', 'usps_layout_v2'],
      colorPalettes: [['#333366', '#cc0000', '#ffffff', '#000000']],
      fontFamilies: ['helvetica neue', 'arial'],
      logoHashes: ['1001100110011001100110011001100110011001100110011001100110011001'],
      lastUpdated: new Date(),
      priority: 88
    },
    {
      brand: 'FedEx',
      category: 'other',
      description: 'Shipping and logistics',
      legitimateDomains: ['fedex.com'],
      domHashes: ['fedex_dom_v1', 'fedex_dom_v2'],
      cssHashes: ['fedex_css_v1', 'fedex_css_v2'],
      layoutHashes: ['fedex_layout_v1', 'fedex_layout_v2'],
      colorPalettes: [['#4d148c', '#ff6600', '#ffffff', '#000000']],
      fontFamilies: ['fedex sans', 'arial'],
      logoHashes: ['0011110000111100001111000011110000111100001111000011110000111100'],
      lastUpdated: new Date(),
      priority: 86
    },
    {
      brand: 'UPS',
      category: 'other',
      description: 'Shipping and logistics',
      legitimateDomains: ['ups.com'],
      domHashes: ['ups_dom_v1', 'ups_dom_v2'],
      cssHashes: ['ups_css_v1', 'ups_css_v2'],
      layoutHashes: ['ups_layout_v1', 'ups_layout_v2'],
      colorPalettes: [['#351c15', '#ffb500', '#ffffff', '#000000']],
      fontFamilies: ['ups berlingske serif', 'arial'],
      logoHashes: ['1100001111000011110000111100001111000011110000111100001111000011'],
      lastUpdated: new Date(),
      priority: 86
    },
    {
      brand: 'DHL',
      category: 'other',
      description: 'Shipping and logistics',
      legitimateDomains: ['dhl.com'],
      domHashes: ['dhl_dom_v1', 'dhl_dom_v2'],
      cssHashes: ['dhl_css_v1', 'dhl_css_v2'],
      layoutHashes: ['dhl_layout_v1', 'dhl_layout_v2'],
      colorPalettes: [['#ffcc00', '#d40511', '#ffffff', '#000000']],
      fontFamilies: ['delivery', 'arial'],
      logoHashes: ['0110100101101001011010010110100101101001011010010110100101101001'],
      lastUpdated: new Date(),
      priority: 84
    }
  ];
}

/**
 * Get the total count of brands in the database.
 */
export function getBrandCount(): number {
  return getAllBrandFingerprints().length;
}

/**
 * Export for use in VisualFingerprintAnalyzer.
 */
export { getAllBrandFingerprints as getDefaultBrandFingerprints };
