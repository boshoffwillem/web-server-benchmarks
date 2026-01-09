import http from 'k6/http';
import { check } from 'k6';

// Stress until failure: gradually increase VUs until a failure occurs
export let options = {
  stages: [
    // { duration: '60s', target: 250 },
    // { duration: '60s', target: 500 },
    // { duration: '60s', target: 1000 },
    // { duration: '60s', target: 2000 },
    // { duration: '60s', target: 4000 },
    { duration: '300s', target: 1000 },
  ],
  thresholds: {
    http_req_failed: ['rate===0'], // Stop on first failure
  },
};

const BASE_URL = 'http://localhost:8080';

export function setup() {
  // Login to get JWT token
  const loginPayload = {
    email: 'gianfranco@email.com',
    password: 'Test123!',
  };

  const loginResponse = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify(loginPayload),
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );

  check(loginResponse, {
    'login successful': (r) => r.status === 200,
    'login returns token': (r) => r.json().token !== undefined,
  });

  return { token: loginResponse.json().token };
}

export default function(data) {
  const token = data.token;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  // Get all products
  const productsResponse = http.get(`${BASE_URL}/api/v1/product`, { headers });

  check(productsResponse, {
    'get products successful': (r) => r.status === 200,
    'products response has products array': (r) => r.json().products !== undefined,
  });

  if (productsResponse.status !== 200) {
    return;
  }

  const products = productsResponse.json().products;

  // Take first 10 products
  // randomly select 10 products from the list

  const firstIndex = Math.floor(Math.random() * (products.length - 10));
  const productsSlice = products.slice(firstIndex, firstIndex + 10);

  for (const product of productsSlice) {
    // Get individual product
    const productResponse = http.get(`${BASE_URL}/api/v1/product/${product.id}`, { headers });

    check(productResponse, {
      'get individual product successful': (r) => r.status === 200,
      'individual product response has product': (r) => r.json().product !== undefined,
    });

    if (productResponse.status !== 200) {
      continue;
    }

    const detailedProduct = productResponse.json().product;

    // Get category using categoryId from product
    const categoryResponse = http.get(`${BASE_URL}/api/v1/category/${detailedProduct.categoryId}`, { headers });

    check(categoryResponse, {
      'get category successful': (r) => r.status === 200,
      'category response has category': (r) => r.json().category !== undefined,
    });

    // Get user using userId from product
    const userResponse = http.get(`${BASE_URL}/api/v1/user/${detailedProduct.userId}`, { headers });

    check(userResponse, {
      'get user successful': (r) => r.status === 200,
      'user response has user': (r) => r.json().user !== undefined,
    });
  }
}
