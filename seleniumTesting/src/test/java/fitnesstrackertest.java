import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class fitnesstrackertest {

    private static WebDriver webDriver;
    private static String baseUrl;
    private static WebDriverWait wait;
    String username= "DarioK";
    String password= "enadario1";
    private static JavascriptExecutor js;

    private static Actions actions;
    private WebDriver webDriver1;


    @BeforeAll
    public static void setUp() {
        System.setProperty("webdriver.chrome.driver", "C:/Drive/chromedriver.exe");

        ChromeOptions options = new ChromeOptions();
        options.addArguments("--remote-allow-origins=*");
        //options.addArguments("--disable-blink-features=AutomationControlled");
        options.addArguments("--start-maximized");
        //options.addArguments("--window-size=1024,768");
        webDriver = new ChromeDriver(options);
        js = (JavascriptExecutor) webDriver;
        wait = new WebDriverWait(webDriver, Duration.ofSeconds(7));
        actions = new Actions(webDriver);
        //baseUrl = "https://www.netflix.com/";
    }

    public void login() throws InterruptedException {
        webDriver.get("https://se-project-7kfh.onrender.com/");
        webDriver.manage().window().maximize();
        Thread.sleep(3000);
        webDriver.findElement(By.xpath("/html/body/header/nav/div[2]/div[2]/a[1]")).click();
        Thread.sleep(3000);
        webDriver.findElement(By.xpath("/html/body/div/section/form/div[1]/input")).sendKeys("DarioK");
        webDriver.findElement(By.xpath("/html/body/div/section/form/div[2]/input")).sendKeys("enadario1");
        Thread.sleep(2000);
        webDriver.findElement(By.xpath("/html/body/div/section/form/button")).click();
        Thread.sleep(3000);
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
        Thread.sleep(3000);
    }

    @Test
    public void testLogin() throws InterruptedException {
        login();
        assertTrue(webDriver.getPageSource().contains("Welcome,"));
        webDriver.quit();
    }

    @Test
    public void testAddWorkout() throws InterruptedException {
        login();
        webDriver.findElement(By.xpath("/html/body/header/nav/div[2]/div[1]/a[2]")).click();
        Thread.sleep(5000);
        webDriver.findElement(By.xpath("/html/body/div/div[2]/div[2]")).click();
        Thread.sleep(2000);
        webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/input")).sendKeys("new Workout");
        webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/textarea")).sendKeys("new Workout Description");
        webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/div/button[2]")).click();
        Thread.sleep(2000);
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
        Thread.sleep(5000);
        assertTrue(webDriver.getPageSource().contains("new Workout"));
        assertTrue(webDriver.getPageSource().contains("new Workout Description"));
        webDriver.quit();
    }

    @Test
    public void addExercise() throws InterruptedException {
        login();
        webDriver.findElement(By.xpath("/html/body/header/nav/div[2]/div[1]/a[2]")).click();
        Thread.sleep(5000);
        webDriver.findElement(By.xpath("/html/body/div/div[1]/div[1]/div[3]/button[1]")).click();
        Thread.sleep(5000);
        webDriver.findElement(By.xpath("/html/body/div/div[2]/div[2]")).click();
        Thread.sleep(1000);
        webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/input[1]")).sendKeys("new Exercise");
        webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/textarea")).sendKeys("new Exercise Notes");
        Select category = new Select(webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/select")));
        category.selectByValue("cardio");
        webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/input[2]")).sendKeys("10");
        webDriver.findElement(By.xpath("/html/body/div/div[3]/div/form/div/button[2]")).click();
        Thread.sleep(2000);
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
        Thread.sleep(5000);
        assertTrue(webDriver.getPageSource().contains("new Exercise"));
        assertTrue(webDriver.getPageSource().contains("new Exercise Notes"));
        webDriver.quit();

    }

    @Test
    public void editExercise() throws InterruptedException{
        login();
        webDriver.findElement(By.xpath("/html/body/header/nav/div[2]/div[1]/a[2]")).click();
        Thread.sleep(5000);
        webDriver.findElement(By.xpath("/html/body/div/div[1]/div[1]/div[3]/button[1]")).click();
        Thread.sleep(5000);
        webDriver.findElement(By.xpath("/html/body/div/div[1]/div[1]/div[3]/button[1]")).click();
        Thread.sleep(1000);
        webDriver.findElement(By.xpath("/html/body/div/div[4]/div/form/input[1]")).clear();
        webDriver.findElement(By.xpath("/html/body/div/div[4]/div/form/input[1]")).sendKeys("sss");
        webDriver.findElement(By.xpath("/html/body/div/div[4]/div/form/div/button[2]")).click();
        Thread.sleep(1000);
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
        Thread.sleep(4000);
        assertTrue(webDriver.getPageSource().contains("sss"));
        webDriver.quit();
    }
}
