package com.aidlfuzzer

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aidlfuzzer.fuzzer.FuzzEngine
import com.aidlfuzzer.fuzzer.FuzzResult
import com.aidlfuzzer.fuzzer.ResultType
import com.aidlfuzzer.ui.theme.AIDLFuzzerTheme
import com.aidlfuzzer.utils.ServiceDiscovery
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AIDLFuzzerTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    FuzzerScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FuzzerScreen() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    val discovery = remember { ServiceDiscovery(context) }
    val fuzzEngine = remember { FuzzEngine(context) }

    var services by remember { mutableStateOf<List<ServiceDiscovery.ExportedService>>(emptyList()) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedService by remember { mutableStateOf<ServiceDiscovery.ExportedService?>(null) }
    val isFuzzing by fuzzEngine.isFuzzing.collectAsState()
    val results by fuzzEngine.results.collectAsState()
    val crashFound by fuzzEngine.crashFound.collectAsState()

    // Filter services based on search query
    val filteredServices = remember(services, searchQuery) {
        if (searchQuery.isBlank()) {
            services
        } else {
            services.filter { service ->
                service.packageName.contains(searchQuery, ignoreCase = true) ||
                service.serviceName.contains(searchQuery, ignoreCase = true)
            }
        }
    }

    LaunchedEffect(Unit) {
        services = discovery.discoverAllExportedServices()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("AIDL Fuzzer") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            // Service Selection
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "Select Target Service",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (services.isEmpty()) {
                        CircularProgressIndicator()
                        Text("Discovering services...")
                    } else {
                        Text("Found ${services.size} exported services")

                        Spacer(modifier = Modifier.height(8.dp))

                        // Search bar
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            modifier = Modifier.fillMaxWidth(),
                            placeholder = { Text("Search services...") },
                            leadingIcon = {
                                Icon(Icons.Default.Search, contentDescription = "Search")
                            },
                            trailingIcon = {
                                if (searchQuery.isNotEmpty()) {
                                    IconButton(onClick = { searchQuery = "" }) {
                                        Icon(Icons.Default.Clear, contentDescription = "Clear")
                                    }
                                }
                            },
                            singleLine = true
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        if (filteredServices.isEmpty()) {
                            Text(
                                "No services match \"$searchQuery\"",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        } else {
                            Text("Showing ${filteredServices.size} services")

                            Spacer(modifier = Modifier.height(4.dp))

                            LazyColumn(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(200.dp)
                            ) {
                                items(filteredServices) { service ->
                                    ServiceItem(
                                        service = service,
                                        isSelected = service == selectedService,
                                        onClick = { selectedService = service }
                                    )
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Fuzzing Controls
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "Fuzzing Control",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (selectedService != null) {
                        Text(
                            "Target: ${selectedService!!.packageName}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            "Service: ${selectedService!!.serviceName.split(".").last()}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Status indicator
                    if (isFuzzing) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                if (crashFound) "Crash found! Fuzzing continues..."
                                else "Fuzzing until crash found...",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (crashFound) Color(0xFF4CAF50) else MaterialTheme.colorScheme.primary
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Button(
                            onClick = {
                                selectedService?.let { service ->
                                    scope.launch {
                                        fuzzEngine.fuzzServiceUntilCrash(
                                            service.packageName,
                                            service.serviceName
                                        )
                                    }
                                }
                            },
                            enabled = selectedService != null && !isFuzzing,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.PlayArrow, "Start")
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Fuzz Until Crash")
                        }

                        Spacer(modifier = Modifier.width(8.dp))

                        OutlinedButton(
                            onClick = { fuzzEngine.stop() },
                            enabled = isFuzzing,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Stop, "Stop")
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Stop")
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Results
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "Discovered Vulnerabilities (${results.size})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (results.isEmpty()) {
                        if (isFuzzing) {
                            CircularProgressIndicator()
                            Text("Fuzzing in progress...")
                        } else {
                            Text("No vulnerabilities found yet",
                                style = MaterialTheme.typography.bodySmall)
                        }
                    } else {
                        LazyColumn {
                            items(results) { result ->
                                ResultItem(result)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ServiceItem(
    service: ServiceDiscovery.ExportedService,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .background(
                if (isSelected) MaterialTheme.colorScheme.primaryContainer
                else Color.Transparent
            )
            .padding(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            if (isSelected) Icons.Default.CheckCircle else Icons.Default.Circle,
            contentDescription = null,
            tint = if (isSelected) MaterialTheme.colorScheme.primary
                   else MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.width(8.dp))
        Column {
            Text(
                service.packageName,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                service.serviceName.split(".").last(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun ResultItem(result: FuzzResult) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = when (result.type) {
                ResultType.CRASH -> Color(0xFFFFEBEE)
                ResultType.EXCEPTION -> Color(0xFFFFF3E0)
                ResultType.TIMEOUT -> Color(0xFFFFFDE7)
                ResultType.ANOMALY -> Color(0xFFE8F5E9)
            }
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    "Code ${result.transactionCode}",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    result.type.name,
                    style = MaterialTheme.typography.labelSmall,
                    color = when (result.type) {
                        ResultType.CRASH -> Color.Red
                        ResultType.EXCEPTION -> Color(0xFFFF6F00)
                        ResultType.TIMEOUT -> Color(0xFFFBC02D)
                        ResultType.ANOMALY -> Color.Green
                    },
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Input: ${result.inputDescription}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Text(
                "Result: ${result.resultDescription}",
                style = MaterialTheme.typography.bodySmall,
                color = Color.Red,
                fontWeight = FontWeight.Bold
            )
        }
    }
}
