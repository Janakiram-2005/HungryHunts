import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv, set_key
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime

# --- App Initialization & Configuration ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'a_super_secret_default_key_for_development')

# --- Database Connection ---
try:
    MONGO_URI = os.getenv('MONGO_URI')
    client = MongoClient(MONGO_URI)
    db = client.get_database('hungryhuts_db')
    users_collection = db.users
    vendors_collection = db.vendors
    dishes_collection = db.dishes
    feedback_collection = db.feedback
    orders_collection = db.orders
    print("✅ MongoDB connected successfully!")
except Exception as e:
    print(f"❌ Error connecting to MongoDB: {e}")

# --- DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view that page.', 'error')
            return redirect(url_for('user_login_page'))
        return f(*args, **kwargs)
    return decorated_function

def vendor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'vendor':
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('admin_login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- MAIN PUBLIC ROUTES ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/vendors')
def vendors_list():
    all_vendors = list(vendors_collection.find())
    return render_template('index.html', vendors=all_vendors)

@app.route('/vendor/<vendor_id>')
def vendor_page(vendor_id):
    vendor = vendors_collection.find_one({'_id': ObjectId(vendor_id)})
    all_dishes = list(dishes_collection.find({'vendor_id': ObjectId(vendor_id)}))
    categorized_menu = {"veg": {}, "non_veg": {}}
    for dish in all_dishes:
        category = dish.get("category", "Uncategorized")
        if "Non-Veg" in category:
            meal_type = category.replace("Non-Veg ", "")
            if meal_type not in categorized_menu["non_veg"]: categorized_menu["non_veg"][meal_type] = []
            categorized_menu["non_veg"][meal_type].append(dish)
        else:
            meal_type = category.replace("Veg ", "")
            if meal_type not in categorized_menu["veg"]: categorized_menu["veg"][meal_type] = []
            categorized_menu["veg"][meal_type].append(dish)
    return render_template('vendor_details.html', vendor=vendor, categorized_menu=categorized_menu)

# --- REGISTRATION & LOGIN ROUTES ---
@app.route('/register/customer', methods=['GET', 'POST'])
def customer_register_page():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        if users_collection.find_one({'email': email}):
            flash('An account with this email already exists.', 'error')
            return redirect(url_for('customer_register_page'))
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({"name": name, "email": email, "password_hash": hashed_password, "role": "customer"})
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('user_login_page'))
    return render_template('customer_register.html')

@app.route('/register/vendor', methods=['GET', 'POST'])
def register_vendor_page():
    if request.method == 'POST':
        owner_name = request.form.get('owner_name')
        email = request.form.get('email')
        password = request.form.get('password')
        shop_name = request.form.get('shop_name')
        shop_description = request.form.get('shop_description')
        address = request.form.get('address')
        cuisine_type = [c.strip() for c in request.form.get('cuisine_type').split(',')]
        if users_collection.find_one({'email': email}):
            flash('An account with this email already exists.', 'error')
            return redirect(url_for('register_vendor_page'))
        hashed_password = generate_password_hash(password)
        user_result = users_collection.insert_one({"name": owner_name, "email": email, "password_hash": hashed_password, "role": "vendor"})
        vendors_collection.insert_one({"owner_id": user_result.inserted_id, "shop_name": shop_name, "description": shop_description, "address": address, "cuisine_type": cuisine_type})
        flash('Restaurant registration successful! Please log in.', 'success')
        return redirect(url_for('vendor_login_page'))
    return render_template('register_vendor.html')

@app.route('/login', methods=['GET', 'POST'])
def user_login_page():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = users_collection.find_one({'email': email, 'role': 'customer'})
        if user and check_password_hash(user.get('password_hash', ''), password):
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            return redirect(url_for('vendors_list'))
        else:
            flash('Invalid customer email or password.', 'error')
            return redirect(url_for('user_login_page'))
    return render_template('user_login.html')

@app.route('/vendor/login', methods=['GET', 'POST'])
def vendor_login_page():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = users_collection.find_one({'email': email, 'role': 'vendor'})
        if user and check_password_hash(user.get('password_hash', ''), password):
            session['user_id'] = str(user['_id'])
            session['role'] = 'vendor'
            return redirect(url_for('vendor_dashboard'))
        else:
            flash('Invalid vendor email or password.', 'error')
            return redirect(url_for('vendor_login_page'))
    return render_template('vendor_login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# --- CART AND CHECKOUT ROUTES ---
@app.route('/cart/add/<dish_id>', methods=['POST'])
@login_required
def add_to_cart(dish_id):
    dish = dishes_collection.find_one({'_id': ObjectId(dish_id)})
    if 'cart' not in session: session['cart'] = {}
    cart = session['cart']
    dish_id_str = str(dish['_id'])
    if dish_id_str in cart:
        cart[dish_id_str]['quantity'] += 1
    else:
        cart[dish_id_str] = {'name': dish['name'], 'price': dish['price'], 'quantity': 1, 'vendor_id': str(dish['vendor_id'])}
    session.modified = True
    flash(f"Added '{dish['name']}' to cart!", "success")
    return redirect(url_for('vendor_page', vendor_id=dish['vendor_id']))

@app.route('/cart/delete/<dish_id>', methods=['POST'])
@login_required
def delete_from_cart(dish_id):
    cart = session.get('cart', {})
    if dish_id in cart:
        cart.pop(dish_id)
        session['cart'] = cart
        flash('Item removed from cart.', 'success')
    return redirect(url_for('view_cart'))

@app.route('/cart')
@login_required
def view_cart():
    cart = session.get('cart', {})
    cart_items, grand_total = [], 0
    for item_id, item in cart.items():
        total = item['price'] * item['quantity']
        cart_items.append({'id': item_id, **item, 'total': total})
        grand_total += total
    return render_template('cart.html', cart_items=cart_items, grand_total=grand_total)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart: return redirect(url_for('vendors_list'))
    
    booking_option = request.form.get('booking_time')
    scheduled_time = request.form.get('scheduled_time') if booking_option == 'later' else 'ASAP'
    payment_method = request.form.get('payment_method')
    address = request.form.get('address')
    
    order_items = [{'name': v['name'], 'price': v['price'], 'quantity': v['quantity']} for k, v in cart.items()]
    grand_total = sum(item['price'] * item['quantity'] for item in order_items)
    vendor_id = next(iter(cart.values()))['vendor_id']

    result = orders_collection.insert_one({
        'user_id': ObjectId(session['user_id']), 'vendor_id': ObjectId(vendor_id),
        'items': order_items, 'grand_total': grand_total, 'booking_time': scheduled_time,
        'payment_method': payment_method, 'delivery_address': address, 'status': 'Pending',
        'ordered_at': datetime.datetime.utcnow()
    })
    
    session.pop('cart', None)
    return redirect(url_for('order_confirmation', order_id=result.inserted_id))



@app.route('/order_confirmation')
@login_required
def order_confirmation():
    # This function now simply shows the confirmation page
    return render_template('order_confirmation.html')



# --- DASHBOARD, PROFILE & VENDOR MANAGEMENT ---
@app.route('/profile')
@login_required
def profile_dashboard():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('profile_dashboard.html', user=user)

@app.route('/vendor/dashboard')
@vendor_required
def vendor_dashboard():
    vendor = vendors_collection.find_one({'owner_id': ObjectId(session['user_id'])})
    if not vendor: return "<h1>Vendor profile not found.</h1>", 404
    
    pipeline = [
        {"$match": {"vendor_id": vendor['_id']}},
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "customer_info"}},
        {"$sort": {"ordered_at": -1}}
    ]
    orders = list(orders_collection.aggregate(pipeline))
    
    return render_template('vendor_dashboard.html', vendor=vendor, orders=orders)

@app.route('/vendor/menu')
@vendor_required
def manage_menu():
    vendor = vendors_collection.find_one({'owner_id': ObjectId(session['user_id'])})
    if not vendor: return "<h1>Vendor profile not found.</h1>", 404
    
    dishes = list(dishes_collection.find({'vendor_id': vendor['_id']}))
    return render_template('manage_menu.html', vendor=vendor, dishes=dishes)

@app.route('/vendor/order/update_status/<order_id>', methods=['POST'])
@vendor_required
def update_order_status(order_id):
    vendor = vendors_collection.find_one({'owner_id': ObjectId(session['user_id'])})
    new_status = request.form.get('status')
    
    # Security check: ensure the order belongs to this vendor
    order = orders_collection.find_one({'_id': ObjectId(order_id), 'vendor_id': vendor['_id']})
    if order and new_status:
        orders_collection.update_one({'_id': order['_id']}, {'$set': {'status': new_status}})
        flash('Order status updated!', 'success')

    return redirect(url_for('vendor_dashboard'))

@app.route('/vendor/<vendor_id>/add_dish', methods=['POST'])
@vendor_required
def add_dish(vendor_id):
    # This logic now redirects back to the new menu page
    try:
        dish_name = request.form.get('dish_name')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        category = request.form.get('category')
        dishes_collection.insert_one({"vendor_id": ObjectId(vendor_id), "name": dish_name, "description": description, "price": price, "category": category})
        flash(f"'{dish_name}' added to your menu.", "success")
    except (ValueError, TypeError):
        flash("Invalid price entered. Please enter a number.", "error")
    return redirect(url_for('manage_menu'))

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def submit_feedback():
    if request.method == 'POST':
        message = request.form.get('message')
        feedback_collection.insert_one({'user_id': ObjectId(session['user_id']), 'message': message, 'submitted_at': datetime.datetime.utcnow()})
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('vendor_dashboard' if session.get('role') == 'vendor' else 'profile_dashboard'))
    return render_template('feedback.html')

@app.route('/vendor/edit')
@vendor_required
def edit_vendor():
    vendor = vendors_collection.find_one({'owner_id': ObjectId(session['user_id'])})
    return render_template('edit_vendor_dashboard.html', vendor=vendor)

@app.route('/vendor/update', methods=['POST'])
@vendor_required
def update_vendor():
    vendor = vendors_collection.find_one({'owner_id': ObjectId(session['user_id'])})
    vendors_collection.update_one({'_id': vendor['_id']}, {'$set': {'shop_name': request.form.get('shop_name'), 'description': request.form.get('shop_description')}})
    flash('Your profile has been updated!', 'success')
    return redirect(url_for('vendor_dashboard'))

@app.route('/vendor/delete', methods=['POST'])
@vendor_required
def delete_vendor():
    owner_id = ObjectId(session['user_id'])
    vendor = vendors_collection.find_one({'owner_id': owner_id})
    if vendor:
        dishes_collection.delete_many({'vendor_id': vendor['_id']})
        vendors_collection.delete_one({'_id': vendor['_id']})
        users_collection.delete_one({'_id': owner_id})
        session.clear()
        flash('Your account and restaurant have been permanently deleted.', 'success')
    return redirect(url_for('home'))

@app.route('/order/cancel/<order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    if order and order['user_id'] == ObjectId(session['user_id']):
        if order['status'] == 'Pending':
            orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': {'status': 'Cancelled'}})
            flash('Your order has been cancelled.', 'success')
        else:
            flash('This order can no longer be cancelled.', 'error')
    else:
        flash('You do not have permission to cancel this order.', 'error')
    return redirect(url_for('my_orders'))

@app.route('/my_orders')
@login_required
def my_orders():
    if session.get('role') != 'customer': return redirect(url_for('home'))
    pipeline = [{"$match": {"user_id": ObjectId(session['user_id'])}}, {"$lookup": {"from": "vendors", "localField": "vendor_id", "foreignField": "_id", "as": "vendor_info"}}, {"$sort": {"ordered_at": -1}}]
    user_orders = list(orders_collection.aggregate(pipeline))
    return render_template('my_orders.html', orders=user_orders)

@app.route('/track_order/<order_id>')
@login_required
def track_order(order_id):
    return render_template('track_order.html')

# --- ADMIN ROUTES ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == os.getenv('ADMIN_USERNAME') and password == os.getenv('ADMIN_PASSWORD'):
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'error')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    pipeline = [{"$lookup": {"from": "users", "localField": "owner_id", "foreignField": "_id", "as": "owner_info"}}]
    all_vendors = list(vendors_collection.aggregate(pipeline))
    return render_template('admin_dashboard.html', vendors=all_vendors)

@app.route('/admin/vendor/<vendor_id>/details')
@admin_required
def admin_vendor_details(vendor_id):
    pipeline = [{"$match": {"_id": ObjectId(vendor_id)}}, {"$lookup": {"from": "users", "localField": "owner_id", "foreignField": "_id", "as": "owner_info"}}]
    vendor_list = list(vendors_collection.aggregate(pipeline))
    if not vendor_list: return "<h1>Vendor not found</h1>", 404
    return render_template('admin_vendor_details.html', vendor=vendor_list[0])

@app.route('/admin/vendor/<vendor_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_vendor(vendor_id):
    vendor = vendors_collection.find_one({'_id': ObjectId(vendor_id)})
    if not vendor: return "<h1>Vendor not found</h1>", 404
    if request.method == 'POST':
        commission_rate = request.form.get('commission_rate')
        is_active = request.form.get('is_active') == 'true'
        vendors_collection.update_one({'_id': ObjectId(vendor_id)}, {'$set': {'commission_rate': float(commission_rate), 'is_active': is_active}})
        flash('Vendor details updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit_vendor.html', vendor=vendor)

@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    pipeline = [{"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "user_info"}}]
    all_feedback = list(feedback_collection.aggregate(pipeline))
    return render_template('admin_feedback.html', feedbacks=all_feedback)

@app.route('/admin/settings', methods=['POST', 'GET'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if new_password and len(new_password) >= 8:
            set_key('.env', 'ADMIN_PASSWORD', new_password)
            flash('Admin password updated. Please log out and log in again.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Password must be at least 8 characters long.', 'error')
    return render_template('admin_settings.html')

@app.route('/order/delete/<order_id>', methods=['POST'])
@login_required
def delete_order(order_id):
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    
    # Security check: Ensure the logged-in user owns this order
    if order and order['user_id'] == ObjectId(session['user_id']):
        # Only allow deletion if the order is not pending
        if order['status'] != 'Pending':
            orders_collection.delete_one({'_id': ObjectId(order_id)})
            flash('Order has been removed from your history.', 'success')
        else:
            flash('You cannot delete a pending order. Please cancel it instead.', 'error')
    else:
        flash('You do not have permission to delete this order.', 'error')

    return redirect(url_for('my_orders'))

# --- RUN THE APP ---
if __name__ == '__main__':
    app.run(debug=True)