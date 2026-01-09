import type { Product } from '../models/product.js';

export class ProductRepository {
  private products: Product[];

  constructor() {
    this.products = [];
    for (let i = 1; i <= 10000; i++) {
      const userId = ((i % 5) + 1).toString();
      const categoryId = ((i % 5) + 1).toString();
      this.products.push({
        id: i.toString(),
        name: `Product ${i}`,
        description: `Description for product ${i}`,
        userId,
        price: i * 1.5,
        categoryId,
      });
    }
  }

  getAllProducts(): Product[] {
    return this.products;
  }

  getProductById(id: string): Product | undefined {
    return this.products.find(p => p.id === id);
  }
}
