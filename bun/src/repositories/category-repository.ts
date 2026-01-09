import type { Category } from '../models/category.js';

export class CategoryRepository {
  private categories: Category[] = [
    { id: '1', name: 'Dairy' },
    { id: '2', name: 'Fruit' },
    { id: '3', name: 'Vegetables' },
    { id: '4', name: 'Bakery' },
    { id: '5', name: 'Meat' },
  ];

  getAllCategories(): Category[] {
    return this.categories;
  }

  getCategoryById(id: string): Category {
    return this.categories.find(c => c.id === id)!;
  }
}
