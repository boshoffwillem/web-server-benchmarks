export class CategoryRepository {
    constructor() {
        this.categories = [
            { id: '1', name: 'Dairy' },
            { id: '2', name: 'Fruit' },
            { id: '3', name: 'Vegetables' },
            { id: '4', name: 'Bakery' },
            { id: '5', name: 'Meat' },
        ];
    }
    getAllCategories() {
        return this.categories;
    }
    getCategoryById(id) {
        return this.categories.find(c => c.id === id);
    }
}
