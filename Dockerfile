FROM php:8.2-apache

WORKDIR /var/www/html

# Install system dependencies and PHP extensions
RUN apt-get update && \
    apt-get install -y \
        zip \
        libzip-dev \
        && \
    docker-php-ext-install \
        pdo \
        pdo_mysql \
        mysqli \
        zip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite headers

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Install PHP dependencies (optimized layer caching)
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-autoloader --no-scripts && \
    composer clear-cache

# Copy application files (after dependencies for better caching)
COPY . .

# Optimize autoloader
RUN composer dump-autoload --optimize

EXPOSE 80
EXPOSE 443